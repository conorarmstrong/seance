//! E01 (EnCase Evidence File) Container Module
//!
//! Provides support for reading forensic disk images in the Expert Witness Format (EWF)
//! commonly known as E01 format, which is the industry standard created by Guidance Software (EnCase).
//!
//! This module uses libewf via FFI bindings to parse E01 images and expose them as
//! DataSource objects for further forensic analysis.
//!
//! A logical evidence file (`.L01`, signature `LVF`) is not an image: its
//! entry tree is walked through libewf's `file_entry` API and each entry
//! published as a `FileEntry` (see [`logical`], HUNT-144).
//!
//! Format features:
//! - Multi-segment support (E01, E02, ..., E99, EAA, ..., ZZZ)
//! - Compression (zlib/deflate)
//! - Error detection (Adler32 checksums)
//! - Metadata storage (case info, acquisition details)

use anyhow::{anyhow, Result};
use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::DataSource,
    module::{ForensicsModule, InputCapability, ModuleError},
};
use serde_json::json;
use std::ffi::{CStr, CString};
use std::path::Path;
use std::ptr;
use tracing::{debug, info, warn};

// Include the generated bindings.
//
// bindgen writes this file; its style is not ours to choose, so the lints that
// judge style are silenced here rather than by editing generated output that is
// rewritten on every build.
//
// `unknown_lints` comes first deliberately. `unnecessary_transmutes` is a recent
// rustc lint, and naming a lint a compiler does not know is itself a warning —
// which under CI's `-D warnings` would trade one broken build for another on any
// toolchain older than the one that introduced it.
#[allow(unknown_lints)]
#[allow(non_upper_case_globals)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(dead_code)]
#[allow(unnecessary_transmutes)]
#[allow(clippy::upper_case_acronyms)]
mod bindings {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

pub mod isolated;
pub mod logical;
pub use isolated::{
    open_e01, open_l01, run_helper, run_logical_helper, IsolatedE01DataSource, OpenedE01, OpenedL01,
};

pub struct E01ContainerModule;

/// DataSource implementation for E01 images using libewf
#[derive(Debug)]
pub struct E01DataSource {
    handle: std::sync::Mutex<*mut bindings::libewf_handle_t>,
    size: u64,
    name: String,
    /// Basenames of the EWF segment files in the set (e.g. 001.E01 .. 001.E18),
    /// in glob order. Empty when opened as a single file without glob.
    segment_files: Vec<String>,
    /// On-disk size of the segment files we could stat, in bytes. This is the
    /// whole set's size only when [`Self::segments_unstatable`] is empty.
    segment_bytes_known: u64,
    /// Segment files that are named in the set but could not be stat'd, with
    /// the OS error. While this is non-empty the set's total size is unknown.
    segments_unstatable: Vec<String>,
}

impl E01DataSource {
    /// Open an E01 image from a file path
    ///
    /// # Safety
    ///
    /// This function contains extensive FFI calls to libewf (C library). The safety guarantees rely on:
    ///
    /// ## Memory Safety Invariants:
    /// 1. **Handle Initialization**: `libewf_handle_initialize` guarantees either:
    ///    - Returns 1 and sets `handle` to valid non-null pointer
    ///    - Returns != 1 and leaves `handle` null (we check and error)
    ///
    /// 2. **Null Pointer Checks**: All pointer returns are validated before dereferencing
    ///
    /// 3. **Error Handling**: libewf uses out-parameters for errors. Passing null for error
    ///    parameter is explicitly allowed by libewf (errors are discarded)
    ///
    /// 4. **String Lifetime**: CString created from `path` lives for entire unsafe block,
    ///    so `.as_ptr()` remains valid for all libewf calls
    ///
    /// 5. **Resource Cleanup**: On any error path, we call `libewf_handle_free` to prevent leaks
    ///
    /// 6. **Glob Memory**: `libewf_glob` allocates memory that MUST be freed with `libewf_glob_free`
    ///    (we ensure this happens even when open succeeds/fails)
    ///
    /// ## Thread Safety:
    /// - The returned handle is wrapped in `Mutex` for thread-safe access
    /// - libewf documentation states handles are NOT thread-safe, hence Mutex requirement
    ///
    /// ## Assumptions About libewf:
    /// - Library is correctly compiled and linked (build.rs ensures this)
    /// - Function signatures in bindings.rs match actual libewf ABI
    /// - libewf handles are opaque pointers that we never dereference directly
    /// - All libewf functions validate their inputs and return error codes
    pub fn open(path: &str) -> Result<Self> {
        // SAFETY: See comprehensive safety documentation above
        unsafe {
            let mut handle: *mut bindings::libewf_handle_t = ptr::null_mut();
            let mut error: *mut bindings::libewf_error_t = ptr::null_mut();

            // Initialize handle
            let ret = bindings::libewf_handle_initialize(&mut handle, &mut error);
            if ret != 1 {
                return Err(anyhow!("Failed to initialize libewf handle"));
            }

            // For multi-segment E01 files, libewf can auto-discover segments if we use glob
            // OR we can pass just the first file and it will find the rest
            // Actually, libewf_handle_open_wide_filenames or libewf_handle_open_file_io_pool
            // might be better, but let's try using glob first

            // Use libewf_glob to find all segments
            let c_path = CString::new(path)?;

            // Full paths of every segment file in the set, captured so we can
            // record the set composition (count, names, on-disk size).
            let mut segment_paths: Vec<String> = Vec::new();

            // First, try to open with glob to get all segments
            let mut number_of_filenames: ::std::os::raw::c_int = 0;
            let mut filenames: *mut *mut ::std::os::raw::c_char = ptr::null_mut();

            // Format 0 = auto-detect (LIBEWF_FORMAT_UNKNOWN)
            let glob_ret = bindings::libewf_glob(
                c_path.as_ptr(),
                c_path.to_bytes().len(),
                0u8,
                &mut filenames,
                &mut number_of_filenames,
                &mut error,
            );

            if glob_ret != 1 {
                debug!("Glob failed, trying single file open for: {}", path);
                // Fall back to single file
                let path_ptr = c_path.as_ptr() as *mut ::std::os::raw::c_char;
                let paths = [path_ptr];
                // number_of_filenames = 1; // Unused

                let access_flags = bindings::libewf_get_access_flags_read();
                let ret = bindings::libewf_handle_open(
                    handle,
                    paths.as_ptr(),
                    1,
                    access_flags,
                    &mut error,
                );

                if ret != 1 {
                    bindings::libewf_handle_free(&mut handle, ptr::null_mut());
                    return Err(anyhow!("Failed to open E01 file: {}", path));
                }
                // Single-file open (glob unavailable): the set is just this file.
                segment_paths.push(path.to_string());
            } else {
                info!("Found {} E01 segment(s) via glob", number_of_filenames);

                // Copy the segment paths out of the C array before it is freed.
                for i in 0..number_of_filenames as isize {
                    let name_ptr = *filenames.offset(i);
                    if !name_ptr.is_null() {
                        segment_paths.push(CStr::from_ptr(name_ptr).to_string_lossy().into_owned());
                    }
                }

                // Get read-only access flags
                let access_flags = bindings::libewf_get_access_flags_read();

                // Open with all segments
                let ret = bindings::libewf_handle_open(
                    handle,
                    filenames as *const *mut ::std::os::raw::c_char,
                    number_of_filenames,
                    access_flags,
                    &mut error,
                );

                // Free the glob filenames
                bindings::libewf_glob_free(filenames, number_of_filenames, ptr::null_mut());

                if ret != 1 {
                    bindings::libewf_handle_free(&mut handle, ptr::null_mut());
                    return Err(anyhow!("Failed to open E01 segments: {}", path));
                }
            }

            // Get media size
            let mut media_size: u64 = 0;
            let ret = bindings::libewf_handle_get_media_size(handle, &mut media_size, &mut error);
            if ret != 1 {
                bindings::libewf_handle_close(handle, ptr::null_mut());
                bindings::libewf_handle_free(&mut handle, ptr::null_mut());
                return Err(anyhow!("Failed to get E01 media size"));
            }

            debug!("Opened E01 image: {} (size: {} bytes)", path, media_size);

            // Refuse "read zero chunk on error": a chunk libewf cannot decode
            // must raise an error, never arrive as zeroes that are
            // byte-for-byte a region that held zeroes. The return code is
            // checked, because a request libewf did not accept leaves its own
            // default governing and nothing on the record would say so.
            let ret = bindings::libewf_handle_set_read_zero_chunk_on_error(handle, 0, &mut error);
            let zero_chunk_error = take_error(&mut error);
            if let Err(e) = zero_substitution_refused(ret) {
                let e = match zero_chunk_error {
                    Some(detail) => e.context(detail),
                    None => e,
                };
                bindings::libewf_handle_close(handle, ptr::null_mut());
                bindings::libewf_handle_free(&mut handle, ptr::null_mut());
                return Err(e);
            }

            // Segment basenames (for display) and total on-disk size of the set.
            let segment_files: Vec<String> = segment_paths
                .iter()
                .map(|p| {
                    Path::new(p)
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_else(|| p.clone())
                })
                .collect();
            // Sum the on-disk size of every segment. A segment we cannot stat
            // must not be quietly dropped from the total: `segment_count` still
            // lists its name, so the sum would understate the size of the set
            // while presenting as the size of the set (B7-030). Track the
            // unstatable ones and let the metadata report the total as unknown.
            let (segment_bytes_known, segments_unstatable) = measure_segment_bytes(&segment_paths);

            Ok(E01DataSource {
                handle: std::sync::Mutex::new(handle),
                size: media_size,
                name: path.to_string(),
                segment_files,
                segment_bytes_known,
                segments_unstatable,
            })
        }
    }

    /// Get metadata from the E01 image
    ///
    /// # Safety
    ///
    /// This function uses FFI to extract metadata from an opened E01 handle.
    ///
    /// ## Safety Invariants:
    /// 1. **Handle Validity**: The handle was created by `open()` and is guaranteed valid until `Drop`
    ///
    /// 2. **Mutex Protection**: We hold a lock on the handle, preventing concurrent access
    ///    (libewf handles are not thread-safe)
    ///
    /// 3. **Two-Phase Queries**: libewf metadata access requires:
    ///    - First call: Get size with `get_utf8_header_value_size`
    ///    - Second call: Get value with `get_utf8_header_value` into pre-allocated buffer
    ///    - We validate return codes at each step
    ///
    /// 4. **Buffer Safety**: We allocate Vec<u8> of exact size returned by libewf,
    ///    so buffer overflow is impossible (libewf validates buffer size parameter)
    ///
    /// 5. **UTF-8 Validation**: libewf returns UTF-8 data, but we still validate with
    ///    `CStr::from_bytes_until_nul` which safely handles invalid UTF-8
    ///
    /// 6. **Error Parameter**: Passing `&mut error` and checking return codes ensures
    ///    we don't proceed on failure (null error is allowed by libewf)
    pub fn get_metadata(&self) -> Result<serde_json::Value> {
        let handle = self.handle.lock().map_err(|_| anyhow!("Mutex poisoned"))?;

        // SAFETY: See safety documentation above
        unsafe {
            let mut error: *mut bindings::libewf_error_t = ptr::null_mut();
            let mut metadata = json!({});

            // Helper function to get header value by identifier
            let mut get_header_value = |identifier: &str| -> Option<String> {
                let c_identifier = CString::new(identifier).ok()?;
                let mut value_size: usize = 0;

                // Get size first
                if bindings::libewf_handle_get_utf8_header_value_size(
                    *handle,
                    c_identifier.as_ptr().cast::<u8>(),
                    identifier.len(),
                    &mut value_size,
                    &mut error,
                ) != 1
                    || value_size == 0
                {
                    take_error(&mut error);
                    return None;
                }

                // Get value
                let mut buffer = vec![0u8; value_size];
                if bindings::libewf_handle_get_utf8_header_value(
                    *handle,
                    c_identifier.as_ptr().cast::<u8>(),
                    identifier.len(),
                    buffer.as_mut_ptr(),
                    buffer.len(),
                    &mut error,
                ) == 1
                {
                    CStr::from_bytes_until_nul(&buffer)
                        .ok()
                        .and_then(|s| s.to_str().ok())
                        .map(|s| s.to_string())
                } else {
                    take_error(&mut error);
                    None
                }
            };

            // Extract common header values
            if let Some(case_num) = get_header_value("case_number") {
                metadata["case_number"] = json!(case_num);
            }
            if let Some(desc) = get_header_value("description") {
                metadata["description"] = json!(desc);
            }
            if let Some(examiner) = get_header_value("examiner_name") {
                metadata["examiner"] = json!(examiner);
            }
            if let Some(evidence_num) = get_header_value("evidence_number") {
                metadata["evidence_number"] = json!(evidence_num);
            }
            if let Some(notes) = get_header_value("notes") {
                metadata["notes"] = json!(notes);
            }
            // Acquisition provenance: when, with what, and from what drive.
            // Previously not asked for at all, though these are ordinary EWF
            // header values read the same two-call way as the five above.
            if let Some(acquiry_date) = get_header_value("acquiry_date") {
                metadata["acquiry_date"] = json!(acquiry_date);
            }
            if let Some(software) = get_header_value("acquiry_software_version") {
                metadata["acquiry_software_version"] = json!(software);
            }
            if let Some(os) = get_header_value("acquiry_operating_system") {
                metadata["acquiry_operating_system"] = json!(os);
            }
            if let Some(serial) = get_header_value("serial_number") {
                metadata["serial_number"] = json!(serial);
            }
            if let Some(model) = get_header_value("model") {
                metadata["model"] = json!(model);
            }

            // Get number of sectors
            let mut sectors: u64 = 0;
            if bindings::libewf_handle_get_number_of_sectors(*handle, &mut sectors, &mut error) == 1
            {
                metadata["sectors"] = json!(sectors);
            }
            take_error(&mut error);

            // Get bytes per sector
            let mut bytes_per_sector: u32 = 0;
            if bindings::libewf_handle_get_bytes_per_sector(
                *handle,
                &mut bytes_per_sector,
                &mut error,
            ) == 1
            {
                metadata["bytes_per_sector"] = json!(bytes_per_sector);
            }
            take_error(&mut error);

            // Which EWF variant, how the chunks were compressed, and how many
            // there are. None of these were asked for before, so the record
            // could not say which of the EWF-family formats an image was, nor
            // how it was compressed, nor how many chunks it held.
            let mut ewf_format: u8 = 0;
            if bindings::libewf_handle_get_format(*handle, &mut ewf_format, &mut error) == 1 {
                metadata["ewf_format"] = json!(ewf_format_name(ewf_format));
            }
            take_error(&mut error);

            let mut compression_level: i8 = 0;
            let mut compression_flags: u8 = 0;
            if bindings::libewf_handle_get_compression_values(
                *handle,
                &mut compression_level,
                &mut compression_flags,
                &mut error,
            ) == 1
            {
                metadata["compression_level"] = json!(compression_level_name(compression_level));
            }
            take_error(&mut error);

            // There is no read-path "get number of chunks" accessor in this
            // API (only write-path ones: get_write_amount_of_chunks,
            // get_number_of_chunks_written). What IS available is the chunk
            // size in bytes and the sectors-per-chunk geometry; the chunk
            // count is derived from sectors / sectors_per_chunk, rounded up,
            // and is labelled as computed rather than reported by libewf.
            let mut chunk_size: u32 = 0;
            if bindings::libewf_handle_get_chunk_size(*handle, &mut chunk_size, &mut error) == 1 {
                metadata["chunk_size_bytes"] = json!(chunk_size);
            }
            take_error(&mut error);

            let mut sectors_per_chunk: u32 = 0;
            if bindings::libewf_handle_get_sectors_per_chunk(
                *handle,
                &mut sectors_per_chunk,
                &mut error,
            ) == 1
            {
                metadata["sectors_per_chunk"] = json!(sectors_per_chunk);
                if sectors_per_chunk > 0 {
                    if let Some(total_sectors) = metadata.get("sectors").and_then(|v| v.as_u64()) {
                        let spc = u64::from(sectors_per_chunk);
                        metadata["number_of_chunks_computed"] = json!(total_sectors.div_ceil(spc));
                    }
                }
            }
            take_error(&mut error);

            // Acquisition hashes recorded inside the E01 by the imaging tool.
            // Unlike the container-file hash computed at ingest, these are
            // hashes of the DECODED MEDIA — the forensically meaningful value to
            // compare the acquired image against the original evidence. The
            // integrity-verify flow uses stored_md5/stored_sha1 as its baseline.
            let mut get_hash_value = |identifier: &str| -> Option<String> {
                let c_identifier = CString::new(identifier).ok()?;
                let mut value_size: usize = 0;
                if bindings::libewf_handle_get_utf8_hash_value_size(
                    *handle,
                    c_identifier.as_ptr().cast::<u8>(),
                    identifier.len(),
                    &mut value_size,
                    &mut error,
                ) != 1
                    || value_size == 0
                {
                    take_error(&mut error);
                    return None;
                }
                let mut buffer = vec![0u8; value_size];
                if bindings::libewf_handle_get_utf8_hash_value(
                    *handle,
                    c_identifier.as_ptr().cast::<u8>(),
                    identifier.len(),
                    buffer.as_mut_ptr(),
                    buffer.len(),
                    &mut error,
                ) == 1
                {
                    CStr::from_bytes_until_nul(&buffer)
                        .ok()
                        .and_then(|s| s.to_str().ok())
                        .map(|s| s.trim().to_lowercase())
                        .filter(|s| !s.is_empty())
                } else {
                    take_error(&mut error);
                    None
                }
            };
            if let Some(md5) = get_hash_value("MD5") {
                metadata["stored_md5"] = json!(md5);
            }
            if let Some(sha1) = get_hash_value("SHA1") {
                metadata["stored_sha1"] = json!(sha1);
            }

            metadata["media_size"] = json!(self.size);
            metadata["source_file"] = json!(self.name);

            // Multi-segment set composition, so the UI can show that this image
            // spans several files (e.g. 001.E01 .. 001.E18) read as one device.
            metadata["segment_count"] = json!(self.segment_files.len());
            metadata["segment_files"] = json!(self.segment_files);
            // A segment we could not stat leaves the set's on-disk size
            // undetermined. Reporting the partial sum as `segment_bytes_total`
            // would render "could not determine" as a smaller, confident number
            // in the custody UI, so the total is null and the partial sum is
            // published under its own, honest name (B7-030).
            apply_segment_size_metadata(
                &mut metadata,
                self.segment_bytes_known,
                &self.segments_unstatable,
            );

            Ok(metadata)
        }
    }
}

/// Sum the on-disk sizes of an EWF set's segment files.
///
/// Returns the sum of the segments we could stat and a list of the ones we
/// could not, with their OS errors. The second value existing at all is the
/// point: `filter_map(|p| metadata(p).ok())` produced a smaller number that
/// still called itself the set's total, so a missing `.E07` silently shrank
/// the custody figure instead of raising a question (B7-030).
/// The EWF variant a stream declares, via `libewf_handle_get_format`.
///
/// Values are `LIBEWF_FORMAT_*` from `/usr/include/libewf/definitions.h`.
/// bindgen's allowlist here is `allowlist_var("LIBEWF_.*")` and
/// `allowlist_type("libewf_.*")` — this particular enum's members carry no
/// `libewf_`/`LIBEWF_`-prefixed *typedef*, only prefixed *enumerator* names,
/// and this build's generated bindings do not surface them as Rust
/// constants, so the values are transcribed here by hand and must be kept in
/// step with that header. A value this table does not name is reported as
/// exactly that — "unrecognised" plus the byte — rather than folded into
/// "unknown", which is itself `LIBEWF_FORMAT_UNKNOWN` (0x00), a real and
/// distinct answer libewf gives when it could not determine the format.
fn ewf_format_name(format: u8) -> String {
    match format {
        0x00 => "unknown".to_string(),
        0x01 => "EnCase1".to_string(),
        0x02 => "EnCase2".to_string(),
        0x03 => "EnCase3".to_string(),
        0x04 => "EnCase4".to_string(),
        0x05 => "EnCase5".to_string(),
        0x06 => "EnCase6".to_string(),
        0x07 => "EnCase7".to_string(),
        0x0e => "SMART".to_string(),
        0x0f => "FTK Imager".to_string(),
        0x10 => "logical EnCase5".to_string(),
        0x11 => "logical EnCase6".to_string(),
        0x12 => "logical EnCase7".to_string(),
        0x25 => "Linen5".to_string(),
        0x26 => "Linen6".to_string(),
        0x27 => "Linen7".to_string(),
        0x70 => "EWF".to_string(),
        0x71 => "EWFX".to_string(),
        other => format!("unrecognised (0x{other:02x})"),
    }
}

/// The compression level requested at acquisition, via
/// `libewf_handle_get_compression_values`'s `compression_level` out-param
/// (that is libewf's own name for it — see `/usr/include/libewf.h`).
///
/// This is **not** the compression method (zlib/DEFLATE vs bzip2): libewf
/// keeps those as two separate enums, `LIBEWF_COMPRESSION_LEVELS`
/// (`DEFAULT = -1`, `NONE = 0`, `FAST = 1`, `BEST = 2`, from the same header)
/// and `LIBEWF_COMPRESSION_METHODS` (`NONE = 0`, `DEFLATE = 1`, `BZIP2 = 2`),
/// and this build's generated bindings expose no `get_compression_method`
/// accessor at all — there is no libewf call in this crate that answers which
/// codec was used. Standard EWF (E01) only ever uses zlib/DEFLATE regardless
/// of level; bzip2 requires the EWF2/Ex01 format, which `ewf_format` states
/// separately. Same transcription caveat as [`ewf_format_name`].
fn compression_level_name(level: i8) -> String {
    match level {
        -1 => "default".to_string(),
        0 => "none".to_string(),
        1 => "fast".to_string(),
        2 => "best".to_string(),
        other => format!("unrecognised ({other})"),
    }
}

/// Publish which of the three ways this image was opened, onto `metadata`.
///
/// `open_e01` already knows whether libewf ran in the isolated helper
/// subprocess or in this process, and the distinction is a custody fact — a
/// crash on hostile evidence kills only a child in one case and can take the
/// server down in the other — but nothing wrote it onto the artifact; the
/// field existed and was read only by a test.
fn publish_open_mode(isolated: bool, metadata: &mut serde_json::Value) {
    metadata["e01_open_mode"] = json!(if isolated {
        "isolated_helper"
    } else {
        "in_process"
    });
}

fn measure_segment_bytes(segment_paths: &[String]) -> (u64, Vec<String>) {
    let mut known: u64 = 0;
    let mut unstatable: Vec<String> = Vec::new();
    for p in segment_paths {
        match std::fs::metadata(p) {
            Ok(m) => known = known.saturating_add(m.len()),
            Err(e) => {
                warn!("E01 segment {} could not be stat'd: {}", p, e);
                unstatable.push(format!("{p}: {e}"));
            }
        }
    }
    (known, unstatable)
}

/// Write the set's on-disk size into `metadata`, as a total when it is known
/// and as `null` plus a partial figure when it is not.
fn apply_segment_size_metadata(
    metadata: &mut serde_json::Value,
    segment_bytes_known: u64,
    segments_unstatable: &[String],
) {
    if segments_unstatable.is_empty() {
        metadata["segment_bytes_total"] = json!(segment_bytes_known);
        return;
    }
    metadata["segment_bytes_total"] = serde_json::Value::Null;
    metadata["segment_bytes_known"] = json!(segment_bytes_known);
    metadata["segments_unstatable"] = json!(segments_unstatable);
    metadata["inventory_incomplete"] = json!(true);
    metadata["inventory_incomplete_reason"] =
        json!(seance_core::io::IncompleteReason::UnresolvedStructure.as_str());
    // The sentence goes on `inventory_incomplete_detail` as well as `message`:
    // the examiner-facing reader takes its text from `<flag>_detail` and reads
    // nothing named `message`, so this explanation used to reach the screen as
    // the bare token `unresolved_structure`. `message` stays for the consumers
    // already on it.
    let detail = concat!(
        "One or more segment files of this EWF set could not be examined on disk, so the ",
        "set's total size is unknown rather than the partial sum shown"
    );
    metadata["inventory_incomplete_detail"] = json!(detail);
    metadata["message"] = json!(detail);
}

/// Keys written by [`apply_segment_size_metadata`] that must appear on the
/// artifact itself, not only inside the nested `e01_metadata` blob.
const SEGMENT_STAMP_KEYS: [&str; 5] = [
    "inventory_incomplete",
    "inventory_incomplete_reason",
    "inventory_incomplete_detail",
    "segments_unstatable",
    "segment_bytes_known",
];

/// Copy the segment-set completeness stamps from the nested `e01_metadata` blob
/// up to the artifact's top-level metadata.
///
/// Every consumer of the standard incompleteness pair — the frontend's
/// incompleteness reader, the report's completeness census — reads an
/// artifact's TOP-LEVEL metadata. A flag written only into a nested object is
/// written and never rendered, which for the examiner is the same as not
/// writing it at all.
fn hoist_segment_stamps(e01_metadata: &serde_json::Value, metadata: &mut serde_json::Value) {
    for key in SEGMENT_STAMP_KEYS {
        if let Some(value) = e01_metadata.get(key) {
            metadata[key] = value.clone();
        }
    }
}

/// One libewf file entry, freed when dropped.
///
/// # Safety
///
/// Valid only while the handle it came from is open and locked: every
/// `LibewfEntry` is created and dropped inside one `E01DataSource` method that
/// holds the handle's `Mutex` guard for its whole duration, so no entry
/// outlives the lock or the handle.
struct LibewfEntry {
    ptr: *mut bindings::libewf_file_entry_t,
}

impl Drop for LibewfEntry {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            // SAFETY: `ptr` was produced by libewf (root or sub-entry getter),
            // is non-null, and is freed exactly once here.
            unsafe {
                bindings::libewf_file_entry_free(&mut self.ptr, ptr::null_mut());
            }
        }
    }
}

impl LibewfEntry {
    /// Ask libewf one fixed-width question about this entry.
    ///
    /// `Ok(None)` is reserved for a call that answers 0 ("not present"); only
    /// the MD5 getter does, and it does not come through here.
    ///
    /// # Safety
    ///
    /// `call` must be a libewf getter taking this entry, an out-param of `T`
    /// and an error out-param.
    unsafe fn get<T: Default>(
        &self,
        field: &str,
        errors: &mut Vec<String>,
        call: unsafe extern "C" fn(
            *mut bindings::libewf_file_entry_t,
            *mut T,
            *mut *mut bindings::libewf_error_t,
        ) -> ::std::os::raw::c_int,
    ) -> Option<T> {
        let mut value = T::default();
        let mut error: *mut bindings::libewf_error_t = ptr::null_mut();
        let ret = call(self.ptr, &mut value, &mut error);
        let detail = take_error(&mut error);
        if ret == 1 {
            Some(value)
        } else {
            errors.push(format!(
                "{field}: {}",
                detail.unwrap_or_else(|| format!("libewf returned {ret} with no detail"))
            ));
            None
        }
    }

    /// The entry's UTF-8 name by the two-call size-then-value protocol.
    unsafe fn name(&self, errors: &mut Vec<String>) -> (Option<String>, bool) {
        let mut error: *mut bindings::libewf_error_t = ptr::null_mut();
        let mut size: usize = 0;
        let ret = bindings::libewf_file_entry_get_utf8_name_size(self.ptr, &mut size, &mut error);
        if ret != 1 {
            let detail = take_error(&mut error).unwrap_or_default();
            errors.push(format!("name size: {detail}"));
            return (None, false);
        }
        take_error(&mut error);
        // A name libewf says is empty (size 0 or just the terminator) is an
        // empty name, which the root of an L01 legitimately has.
        if size <= 1 {
            return (Some(String::new()), false);
        }
        // The size is libewf's reading of attacker data; a name longer than
        // this is not a name any file system could carry.
        const MAX_NAME_BYTES: usize = 64 * 1024;
        if size > MAX_NAME_BYTES {
            errors.push(format!(
                "name: libewf declared a {size}-byte name, over the {MAX_NAME_BYTES}-byte bound; \
                 not read"
            ));
            return (None, false);
        }
        let mut buf = vec![0u8; size];
        let ret = bindings::libewf_file_entry_get_utf8_name(
            self.ptr,
            buf.as_mut_ptr(),
            buf.len(),
            &mut error,
        );
        if ret != 1 {
            let detail = take_error(&mut error).unwrap_or_default();
            errors.push(format!("name: {detail}"));
            return (None, false);
        }
        take_error(&mut error);
        let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
        match String::from_utf8(buf[..end].to_vec()) {
            Ok(s) => (Some(s), false),
            Err(e) => (
                Some(String::from_utf8_lossy(e.as_bytes()).into_owned()),
                true,
            ),
        }
    }

    /// The MD5 the L01 stores for this entry: `None` when it stores none.
    unsafe fn md5(&self, errors: &mut Vec<String>) -> Option<String> {
        let mut error: *mut bindings::libewf_error_t = ptr::null_mut();
        // 32 hex digits and a terminator; libewf checks the size it is given.
        let mut buf = [0u8; 64];
        let ret = bindings::libewf_file_entry_get_utf8_hash_value_md5(
            self.ptr,
            buf.as_mut_ptr(),
            buf.len(),
            &mut error,
        );
        let detail = take_error(&mut error);
        match ret {
            1 => CStr::from_bytes_until_nul(&buf)
                .ok()
                .and_then(|s| s.to_str().ok())
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty()),
            0 => None,
            _ => {
                errors.push(format!("md5: {}", detail.unwrap_or_default()));
                None
            }
        }
    }
}

/// Narrows a libewf timestamp (u32 or i64 by libewf release) to the u32 facts.
fn narrow_time<T: TryInto<u32>>(t: Option<T>) -> Option<u32> {
    t.and_then(|t| t.try_into().ok())
}

impl logical::EntryNode for LibewfEntry {
    fn facts(&self) -> logical::EntryFacts {
        let mut errors = Vec::new();
        // SAFETY: `self.ptr` is a live entry under the handle lock (see
        // `LibewfEntry`); every getter is passed a matching out-param type.
        unsafe {
            let (name, name_lossy) = self.name(&mut errors);
            let entry_type = self.get("type", &mut errors, bindings::libewf_file_entry_get_type);
            let flags = self.get("flags", &mut errors, bindings::libewf_file_entry_get_flags);
            let size = self.get("size", &mut errors, bindings::libewf_file_entry_get_size);
            let media_data_offset = self.get(
                "media_data_offset",
                &mut errors,
                bindings::libewf_file_entry_get_media_data_offset,
            );
            let media_data_size = self.get(
                "media_data_size",
                &mut errors,
                bindings::libewf_file_entry_get_media_data_size,
            );
            let duplicate_media_data_offset = self.get(
                "duplicate_media_data_offset",
                &mut errors,
                bindings::libewf_file_entry_get_duplicate_media_data_offset,
            );
            let creation_time = self.get(
                "creation_time",
                &mut errors,
                bindings::libewf_file_entry_get_creation_time,
            );
            let modification_time = self.get(
                "modification_time",
                &mut errors,
                bindings::libewf_file_entry_get_modification_time,
            );
            let access_time = self.get(
                "access_time",
                &mut errors,
                bindings::libewf_file_entry_get_access_time,
            );
            let entry_modification_time = self.get(
                "entry_modification_time",
                &mut errors,
                bindings::libewf_file_entry_get_entry_modification_time,
            );
            let md5 = self.md5(&mut errors);
            logical::EntryFacts {
                name,
                name_lossy,
                entry_type,
                flags,
                size,
                media_data_offset,
                media_data_size,
                duplicate_media_data_offset,
                // libewf 20140816 reports these as u32, later releases as i64
                // (the Windows build uses 20240506); narrow to the u32 the
                // facts carry.
                creation_time: narrow_time(creation_time),
                modification_time: narrow_time(modification_time),
                access_time: narrow_time(access_time),
                entry_modification_time: narrow_time(entry_modification_time),
                md5,
                // Filled after the walk, under the same handle lock, by
                // `walk_logical` (HUNT-250).
                placeholder_byte: None,
                errors,
            }
        }
    }

    fn sub_entry_count(&self) -> Result<u32, String> {
        let mut count: ::std::os::raw::c_int = 0;
        let mut error: *mut bindings::libewf_error_t = ptr::null_mut();
        // SAFETY: live entry under the handle lock; `count` is a c_int.
        unsafe {
            let ret = bindings::libewf_file_entry_get_number_of_sub_file_entries(
                self.ptr, &mut count, &mut error,
            );
            let detail = take_error(&mut error);
            if ret != 1 {
                return Err(detail.unwrap_or_else(|| format!("libewf returned {ret}")));
            }
        }
        u32::try_from(count).map_err(|_| format!("libewf reported {count} sub-entries"))
    }

    fn sub_entry(&self, index: u32) -> Result<Self, String> {
        let index = ::std::os::raw::c_int::try_from(index)
            .map_err(|_| format!("sub-entry index {index} does not fit libewf's int"))?;
        let mut sub: *mut bindings::libewf_file_entry_t = ptr::null_mut();
        let mut error: *mut bindings::libewf_error_t = ptr::null_mut();
        // SAFETY: live entry under the handle lock; on success libewf hands
        // over a new entry that `LibewfEntry` then owns and frees.
        unsafe {
            let ret = bindings::libewf_file_entry_get_sub_file_entry(
                self.ptr, index, &mut sub, &mut error,
            );
            let detail = take_error(&mut error);
            if ret != 1 || sub.is_null() {
                return Err(detail.unwrap_or_else(|| format!("libewf returned {ret}")));
            }
        }
        Ok(LibewfEntry { ptr: sub })
    }
}

impl E01DataSource {
    /// The root of the L01 entry tree, `Ok(None)` when libewf reports none.
    ///
    /// # Safety
    ///
    /// `handle` must be the open handle, locked by the caller for as long as
    /// the returned entry lives.
    unsafe fn root_entry(handle: *mut bindings::libewf_handle_t) -> Result<Option<LibewfEntry>> {
        let mut root: *mut bindings::libewf_file_entry_t = ptr::null_mut();
        let mut error: *mut bindings::libewf_error_t = ptr::null_mut();
        let ret = bindings::libewf_handle_get_root_file_entry(handle, &mut root, &mut error);
        let detail = take_error(&mut error);
        match ret {
            1 if !root.is_null() => Ok(Some(LibewfEntry { ptr: root })),
            0 | 1 => Ok(None),
            _ => Err(anyhow!(
                "libewf would not give the logical evidence file's root entry: {}",
                detail.unwrap_or_else(|| format!("libewf returned {ret}"))
            )),
        }
    }

    /// Walk this logical evidence file's entry tree within `limits`
    /// (HUNT-144). The handle is locked for the whole walk, and every libewf
    /// entry the walk holds is freed before the lock is released.
    pub fn walk_logical(&self, limits: logical::WalkLimits) -> Result<logical::LogicalWalk> {
        let handle = self.handle.lock().map_err(|_| anyhow!("Mutex poisoned"))?;
        // SAFETY: the handle is open and locked for the duration.
        let root = unsafe { Self::root_entry(*handle)? };
        let mut walk = logical::walk(root, limits);
        // HUNT-250: the one byte each size-0 placeholder stores, read from the
        // media stream at the entry's own offset while the handle is still
        // locked. A failed or short read is an error on the entry, not a value.
        logical::record_placeholder_bytes(&mut walk, |offset| {
            let mut byte = [0u8; 1];
            let mut error: *mut bindings::libewf_error_t = ptr::null_mut();
            // SAFETY: the handle is open and locked; `byte` is a live 1-byte
            // buffer and its length is what libewf is told.
            // `error` is libewf's own error object, freed by `take_error`.
            let (n, detail) = unsafe {
                let n = bindings::libewf_handle_read_random(
                    *handle,
                    byte.as_mut_ptr() as *mut std::ffi::c_void,
                    1,
                    offset,
                    &mut error,
                );
                (n, take_error(&mut error))
            };
            match n {
                1 => Ok(byte[0]),
                n if n < 0 => Err(detail.unwrap_or_else(|| format!("libewf returned {n}"))),
                n => Err(format!("libewf read {n} bytes at media offset {offset}")),
            }
        });
        Ok(walk)
    }

    /// Read `buf.len()` bytes at `offset` of the entry at `index_path`, through
    /// `libewf_file_entry_read_random` — libewf decides where the entry's bytes
    /// are, including for data EnCase stored once for duplicate files.
    pub fn read_logical_entry(
        &self,
        index_path: &[u32],
        offset: u64,
        buf: &mut [u8],
    ) -> std::io::Result<usize> {
        use logical::EntryNode;
        let handle = self
            .handle
            .lock()
            .map_err(|_| std::io::Error::other("Mutex poisoned"))?;
        let offset = i64::try_from(offset).map_err(|_| {
            std::io::Error::other(format!("offset {offset} is past libewf's range"))
        })?;
        // SAFETY: the handle is open and locked; each entry on the way down is
        // owned by a `LibewfEntry` and freed when replaced or at return.
        unsafe {
            let mut entry = Self::root_entry(*handle)
                .map_err(|e| std::io::Error::other(e.to_string()))?
                .ok_or_else(|| {
                    std::io::Error::other("the logical evidence file has no root entry")
                })?;
            for index in index_path {
                entry = entry.sub_entry(*index).map_err(|e| {
                    std::io::Error::other(format!(
                        "entry {index_path:?} could not be re-opened: {e}"
                    ))
                })?;
            }
            let mut error: *mut bindings::libewf_error_t = ptr::null_mut();
            let n = bindings::libewf_file_entry_read_random(
                entry.ptr,
                buf.as_mut_ptr() as *mut std::ffi::c_void,
                buf.len(),
                offset,
                &mut error,
            );
            if n < 0 {
                let detail = take_error(&mut error).unwrap_or_else(|| "no detail".to_string());
                return Err(std::io::Error::other(format!(
                    "libewf could not read entry {index_path:?} at offset {offset}: {detail}"
                )));
            }
            take_error(&mut error);
            Ok(n as usize)
        }
    }
}

impl DataSource for E01DataSource {
    /// Read data from the E01 image at a specific offset
    ///
    /// # Safety
    ///
    /// This function performs FFI calls to read data from the E01 image.
    ///
    /// ## Safety Invariants:
    /// 1. **Handle Validity**: Handle is valid (created in `open()`, not yet dropped)
    ///
    /// 2. **Mutex Protection**: We hold exclusive lock on handle for thread safety
    ///
    /// 3. **Buffer Validity**: `buf.as_mut_ptr()` is guaranteed valid by Rust's borrow checker
    ///    - Buffer is alive for entire function call
    ///    - Buffer length is passed to libewf, which validates it
    ///    - libewf will not write beyond `buf.len()` bytes
    ///
    /// 4. **Offset Validation**: libewf validates offset against media size internally
    ///    - Reading past end returns short read (< buf.len())
    ///    - Invalid offsets return -1 (we check this)
    ///
    /// 5. **Return Value Semantics**:
    ///    - Positive: Number of bytes read (guaranteed ≤ buf.len())
    ///    - Zero: EOF or zero-length buffer
    ///    - Negative: Error (we check and return Err)
    ///
    /// 6. **Decompression Safety**: libewf handles decompression internally
    ///    (E01 uses zlib compression), we trust the library to validate compressed data
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        let handle = self
            .handle
            .lock()
            .map_err(|_| std::io::Error::other("Mutex poisoned"))?;

        // SAFETY: See safety documentation above
        unsafe {
            let mut error: *mut bindings::libewf_error_t = ptr::null_mut();

            // Use libewf_handle_read_random for true random access
            // This is the correct API for random reads without maintaining seek position
            let bytes_read = bindings::libewf_handle_read_random(
                *handle,
                buf.as_mut_ptr() as *mut std::ffi::c_void,
                buf.len(),
                offset as i64,
                &mut error,
            );

            if bytes_read < 0 {
                // libewf's own words for what went wrong, which is what an
                // examiner asked "why did this image stop reading" needs; the
                // error object is freed in the same step rather than leaked.
                let error_msg = match take_error(&mut error) {
                    Some(detail) => format!("libewf error at offset {offset}: {detail}"),
                    None => format!(
                        "Failed to read from E01 image at offset {offset} (libewf gave no error \
                         details)"
                    ),
                };
                return Err(std::io::Error::other(error_msg));
            }

            Ok(bytes_read as usize)
        }
    }

    fn size(&self) -> u64 {
        self.size
    }

    /// The first segment this source was opened from. The isolated source
    /// implements this and the in-process one inherited the trait default
    /// `None`, so anything resolving a decoded image back to a path behaved
    /// differently depending on whether the helper was available.
    fn get_underlying_path(&self) -> Option<std::path::PathBuf> {
        Some(std::path::PathBuf::from(&self.name))
    }
}

/// Implement Drop to properly close the E01 handle
///
/// # Safety
///
/// This ensures proper cleanup of libewf resources when E01DataSource is dropped.
///
/// ## Safety Invariants:
/// 1. **Double-Free Prevention**: We check `is_null()` before calling free functions
///    to prevent double-free if handle was already cleaned up
///
/// 2. **Mutex Lock**: We attempt to lock the mutex. If poisoned (panic in other thread),
///    we cannot safely free the handle, so we leak it (better than UB)
///
/// 3. **Close Before Free**: libewf requires `handle_close` before `handle_free`
///    - Close releases file descriptors and flushes buffers
///    - Free deallocates the handle structure
///
/// 4. **Error Handling**: We pass null for error parameter (allowed by libewf)
///    since we cannot propagate errors from Drop (it can't fail)
///
/// 5. **No Panic**: This code must not panic (Drop guarantee)
///    - We check all conditions before unsafe calls
///    - No .unwrap() or assertions
impl Drop for E01DataSource {
    fn drop(&mut self) {
        if let Ok(mut handle) = self.handle.lock() {
            // SAFETY: See safety documentation above
            unsafe {
                if !(*handle).is_null() {
                    bindings::libewf_handle_close(*handle, ptr::null_mut());
                    bindings::libewf_handle_free(&mut *handle, ptr::null_mut());
                }
            }
        }
    }
}

/// # Safety - Send + Sync Implementation
///
/// E01DataSource must be Send + Sync to be used as Arc<dyn DataSource> in concurrent contexts.
///
/// ## Send Safety:
/// E01DataSource can be safely transferred between threads because:
///
/// 1. **Opaque Handle**: The libewf_handle_t is an opaque C pointer that doesn't
///    contain thread-local data or thread IDs
///
/// 2. **Owned Resources**: The handle is owned (not borrowed), so moving between
///    threads doesn't create aliasing issues
///
/// 3. **No Thread Affinity**: libewf doesn't use thread-local storage or require
///    operations to happen on the same thread that created the handle
///
/// 4. **Primitive Fields**: `size` (u64) and `name` (String) are both Send
///
/// ## Sync Safety:
/// E01DataSource can be safely shared between threads (&T across threads) because:
///
/// 1. **Mutex Protection**: The handle is wrapped in `std::sync::Mutex`, which provides
///    exclusive access guarantees. Only one thread can access the handle at a time.
///
/// 2. **No Interior Mutability**: Apart from the Mutex-protected handle, all other fields
///    are immutable (size, name) or can be safely shared
///
/// 3. **libewf Thread Safety**: According to libewf documentation:
///    - Handles are NOT thread-safe (hence the Mutex)
///    - But multiple threads can have their own handles to the same file
///    - Our Mutex ensures single-threaded access to each handle instance
///
/// 4. **Read-Only Operations**: All our operations are read-only (no writes to image),
///    which reduces risk of race conditions
///
/// ## Verification (what is actually checked):
/// - Every libewf call on the handle goes through `self.handle.lock()`; there
///   is no path that touches the raw pointer outside the `Mutex`.
/// - The type is handed to the orchestrator's worker pool as
///   `Arc<dyn DataSource>` (`seance_core::module`, `worker_count` workers), so
///   the serialisation above is what the concurrent path relies on.
/// - By default the libewf handle does not live in this process at all: the
///   image is opened in the isolated `seance-ewf-helper` subprocess
///   (`isolated::open_e01`, `SEANCE_E01_ISOLATED`), and this in-process type
///   is the fallback when isolation is off or the helper binary is absent.
/// - There is no ThreadSanitizer or Miri run in CI; an earlier revision of this
///   comment claimed one, and it did not exist.
///
/// ## Alternative Considered:
/// We could use `Arc<Mutex<Handle>>` instead of `Mutex<*mut Handle>`, but this
/// would require an extra Arc allocation. The current design is more efficient
/// while maintaining safety through the Mutex.
unsafe impl Send for E01DataSource {}
unsafe impl Sync for E01DataSource {}

/// libewf's own words for an error, taken and then freed.
///
/// `libewf_error_free` was called nowhere in this crate: every probe for a
/// header or hash value an image does not hold set an error object that was
/// then leaked, and the same variable was reused across the whole of
/// `get_metadata` without being reset, so a later failure could be reported
/// with an earlier error's words. Taking the message and freeing the object is
/// one operation for that reason.
///
/// # Safety
///
/// `error` must be a valid pointer to a libewf error pointer — null or an
/// error libewf set. It is null on return.
unsafe fn take_error(error: &mut *mut bindings::libewf_error_t) -> Option<String> {
    if error.is_null() {
        return None;
    }
    let mut buf = [0 as ::std::os::raw::c_char; 512];
    let printed = bindings::libewf_error_sprint(*error, buf.as_mut_ptr(), buf.len());
    let message = if printed > 0 {
        CStr::from_ptr(buf.as_ptr())
            .to_string_lossy()
            .trim()
            .to_string()
    } else {
        String::new()
    };
    bindings::libewf_error_free(error);
    (!message.is_empty()).then_some(message)
}

/// Which EWF family a file's own first bytes declare, or `None` where they
/// declare none.
///
/// Every EWF segment opens with an 8-byte signature: `EVF\x09\x0d\x0a\xff\x00`
/// for EnCase physical images (`.E01`) and SMART (`.S01`), and
/// `LVF\x09\x0d\x0a\xff\x00` for logical evidence files (`.L01`). The name
/// cannot decide this — a physical image can be named anything — and the
/// distinction matters because the two hold different things: one is an image
/// of a device, the other a container of files.
///
/// `Err` is a third answer and never flattened into `None`: a file this cannot
/// read is not a file that is not EWF.
fn ewf_family(path: &str) -> std::io::Result<Option<EwfFamily>> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut head = [0u8; 8];
    let mut filled = 0usize;
    while filled < head.len() {
        match file.read(&mut head[filled..])? {
            0 => break,
            n => filled += n,
        }
    }
    if filled < head.len() || &head[1..8] != b"VF\x09\x0d\x0a\xff\x00" {
        return Ok(None);
    }
    Ok(match head[0] {
        b'E' | b'S' => Some(EwfFamily::Physical),
        b'L' => Some(EwfFamily::Logical),
        _ => None,
    })
}

/// What an EWF file's signature says it holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EwfFamily {
    /// `EVF` — an image of a device, which is what this module serves.
    Physical,
    /// `LVF` — a logical evidence file: a set of files and their metadata, with
    /// no device image inside it.
    Logical,
}

/// Turn libewf's answer to the zero-substitution request into a decision.
///
/// The request is the one setting this module's honesty about undecodable
/// chunks rests on. libewf returns 1 for success; anything else means the
/// refusal was not established, and an image read under libewf's own default
/// could hand up zeroes for a chunk it could not decode with nothing on the
/// record to say so. That is not an image this module will serve.
fn zero_substitution_refused(ret: ::std::os::raw::c_int) -> Result<()> {
    if ret == 1 {
        return Ok(());
    }
    Err(anyhow!(
        "libewf would not accept the request to stop substituting zeroes for an undecodable \
         chunk (libewf_handle_set_read_zero_chunk_on_error returned {ret}); refusing to open \
         the image rather than serve zeroes that cannot be told from a region that held zeroes"
    ))
}

/// The name of the extracted image: the artifact's own name where it has one,
/// else the file that was opened. An artifact carrying a path and no name used
/// to produce an image called `_extracted`.
fn extracted_name(name: &str, path: &str) -> String {
    if !name.is_empty() {
        return format!("{name}_extracted");
    }
    let base = Path::new(path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    if base.is_empty() {
        "e01_image_extracted".to_string()
    } else {
        format!("{base}_extracted")
    }
}

/// A `ContainerRefusal` record for a container this module will not serve as a
/// disk image.
///
/// An exhibit that produced nothing must never read as an exhibit that held
/// nothing, and a refusal travelling only as an error into the processing log
/// is a refusal the artifact tree does not show.
fn refusal_record(artifact: &Artifact, name: &str, path: &str, detail: String) -> Artifact {
    let m = json!({
        "type": "ContainerRefusal",
        "subtype": "ewf_logical_evidence",
        "name": format!("{name}: logical evidence file could not be read"),
        "short_desc": "EWF logical evidence file (L01): its entries could not be read",
        "container": "ewf_logical",
        "container_path": path,
        "module": "container.e01_reader",
        "content_incomplete": true,
        "content_incomplete_reason": "unresolved_structure",
        "content_incomplete_detail": detail.clone(),
        "detail": detail,
    });
    Artifact::new(artifact.case_id, ArtifactType::ParsedRecord, None, m)
        .with_parent(artifact.id)
        .with_subtype("ewf_logical_evidence")
}

/// Walk a logical evidence file and publish what it holds (HUNT-144).
///
/// A file libewf cannot open or walk yields the refusal record rather than an
/// error, so the artifact tree shows that this exhibit produced nothing and
/// why: an exhibit that produced nothing must never read as one that held
/// nothing.
fn process_logical(artifact: &Artifact, name: &str, path: &str) -> Vec<Artifact> {
    match isolated::open_l01(path) {
        Ok(opened) => logical_artifacts(artifact, name, path, &opened),
        Err(e) => {
            warn!(
                "E01 module could not walk logical evidence file {}: {}",
                path, e
            );
            let detail = format!(
                "'{name}' is an EWF logical evidence file (its signature is LVF, not EVF): a \
                 container of files and their metadata, not an image of a device. libewf could \
                 not open it or walk its entry table ({e}), so its contents were NOT recovered \
                 and no disk image was published from it. Any file inside it is unexamined."
            );
            vec![refusal_record(artifact, name, path, detail)]
        }
    }
}

/// libewf's entry-type byte as a word, and whether it is a directory.
fn l01_entry_type_name(entry_type: Option<u8>) -> String {
    match entry_type {
        Some(logical::ENTRY_TYPE_DIRECTORY) => "directory".to_string(),
        Some(logical::ENTRY_TYPE_FILE) => "file".to_string(),
        Some(other) => format!("unrecognised (0x{other:02x})"),
        None => "unread".to_string(),
    }
}

/// The artifacts for one walked L01: an inventory record stating what the
/// walk covered, then one `FileEntry` per entry, flat under the container like
/// a ZIP's, in the walk's pre-order.
fn logical_artifacts(
    artifact: &Artifact,
    name: &str,
    path: &str,
    opened: &isolated::OpenedL01,
) -> Vec<Artifact> {
    let walk = &opened.walk;
    let mut out = Vec::with_capacity(walk.entries.len() + 1);
    let mut paths: Vec<String> = Vec::with_capacity(walk.entries.len());
    let mut entries: Vec<Artifact> = Vec::with_capacity(walk.entries.len());
    let mut unreadable_names = 0usize;
    let mut entries_with_field_errors = 0usize;
    // HUNT-246: directory data served as a stream, and the one-byte
    // empty-entry form counted.
    let mut directory_data_streams = 0usize;
    let mut directory_placeholders = 0usize;
    let mut directory_placeholder_values = 0usize;
    // HUNT-250: whether each placeholder's byte lies in a span no other walked
    // entry's stored data covers. Only a complete walk in which every entry's
    // span is known can say so of the file: an entry whose span libewf would
    // not give could cover any byte.
    let spans = logical::stored_spans(walk);
    let span_checked = !walk.is_incomplete() && spans.unknown == 0;
    let mut directory_placeholders_alone = 0usize;
    let mut directory_placeholders_shared = 0usize;
    let mut directory_data_unserved = 0usize;
    // HUNT-247: (position in `entries`, walk ordinal) of each sparse entry,
    // settled once every entry's path is known.
    let mut sparse_entries: Vec<(usize, usize)> = Vec::new();
    // Walk ordinal -> position in `entries` (directory streams are
    // interleaved, so the two differ).
    let mut position_of: Vec<usize> = Vec::with_capacity(walk.entries.len());

    for (ordinal, entry) in walk.entries.iter().enumerate() {
        let facts = &entry.facts;
        let (entry_name, name_unreadable) = match &facts.name {
            Some(n) => (n.clone(), false),
            None => {
                unreadable_names += 1;
                (format!("[unreadable name: entry {ordinal}]"), true)
            }
        };
        // The decoder guarantees a parent precedes its child.
        let parent_path = entry.parent.map(|p| paths[p as usize].clone());
        let full_path = match &parent_path {
            None => format!("/{entry_name}"),
            Some(pp) if pp == "/" => format!("/{entry_name}"),
            Some(pp) => format!("{pp}/{entry_name}"),
        };
        paths.push(full_path.clone());

        let is_directory = facts.entry_type == Some(logical::ENTRY_TYPE_DIRECTORY);
        let size = facts.size.or(facts.media_data_size);
        let mut m = json!({
            "name": entry_name,
            "path": full_path,
            "parent_path": parent_path.unwrap_or_default(),
            "size": size,
            "is_directory": is_directory,
            "container": "ewf_logical",
            "container_path": path,
            "l01_entry_ordinal": ordinal,
            "l01_index_path": entry.index_path,
            "l01_entry_type": l01_entry_type_name(facts.entry_type),
            "l01_flags": facts.flags,
            "l01_media_data_offset": facts.media_data_offset,
            "l01_media_data_size": facts.media_data_size,
            "l01_duplicate_media_data_offset": facts.duplicate_media_data_offset,
            "l01_sub_entries": entry.sub_entries,
        });
        if name_unreadable {
            m["name_unreadable"] = json!(true);
        }
        if facts.name_lossy {
            m["name_lossy_utf8"] = json!(true);
        }
        if entry_name.contains('/') {
            // The path joins names with `/`; this name carries one, so the path
            // alone does not say where the entry sits. `l01_index_path` does.
            m["name_contains_path_separator"] = json!(true);
        }
        // The four times, under the L01's own names as POSIX seconds, and the
        // timeline's vocabulary as RFC 3339 UTC. 0 is how an L01 says a time
        // was not recorded, so it is published raw and projected nowhere.
        // "Entry modified" is the time the entry's metadata last changed, which
        // is what the timeline calls `changed` (Metadata Changed).
        for (raw, key, projected) in [
            (facts.creation_time, "l01_creation_time", "created"),
            (facts.modification_time, "l01_modification_time", "modified"),
            (facts.access_time, "l01_access_time", "accessed"),
            (
                facts.entry_modification_time,
                "l01_entry_modification_time",
                "changed",
            ),
        ] {
            if let Some(ts) = raw {
                m[key] = json!(ts);
                if let Some(rfc) = logical::posix_to_rfc3339(ts) {
                    m[projected] = json!(rfc);
                    m["timezone"] = json!("UTC");
                }
            }
        }
        if let Some(md5) = &facts.md5 {
            // The container's own record of this entry's content hash, which
            // Verify Integrity compares the served bytes against.
            m["stored_md5"] = json!(md5);
            m["stored_hash_source"] = json!("l01_entry");
        }
        if !facts.errors.is_empty() {
            entries_with_field_errors += 1;
            m["l01_field_errors"] = json!(facts.errors);
        }
        if entry.sub_entries_not_walked > 0 {
            m["l01_sub_entries_not_walked"] = json!(entry.sub_entries_not_walked);
        }

        let mut data: Option<std::sync::Arc<dyn DataSource>> = None;
        if !is_directory {
            let sparse = facts
                .flags
                .is_some_and(|f| f & logical::ENTRY_FLAG_SPARSE_DATA != 0);
            let short_media = matches!(
                (facts.size, facts.media_data_size),
                (Some(s), Some(ms)) if ms < s
            );
            match size {
                Some(size) => {
                    data = Some(std::sync::Arc::new(
                        seance_core::data_source::CachingDataSource::new(
                            std::sync::Arc::new(logical::LogicalEntrySource::new(
                                opened.backend.clone(),
                                ordinal as u32,
                                size,
                            )),
                            64 * 1024,
                            4 * 1024 * 1024,
                        ),
                    ));
                }
                None => {
                    m["content_incomplete"] = json!(true);
                    m["content_incomplete_reason"] =
                        json!(seance_core::io::IncompleteReason::UnresolvedStructure.as_str());
                    m["content_incomplete_detail"] = json!(
                        "libewf would give neither this entry's size nor its stored data size, \
                         so its bytes are not served"
                    );
                }
            }
            if sparse {
                // Settled after the walk (`settle_sparse_entry`): what libewf
                // serves depends on another entry this loop may not have
                // reached yet.
                sparse_entries.push((entries.len(), ordinal));
            } else if short_media {
                m["content_incomplete"] = json!(true);
                m["content_incomplete_reason"] =
                    json!(seance_core::io::IncompleteReason::ShortRead.as_str());
                m["content_incomplete_detail"] = json!(
                    "The L01 stores less data for this entry than its recorded size, so reading \
                     it may end short of that size"
                );
            }
        }

        // HUNT-246: EnCase stores data against directory entries too (on the
        // NGDC phone L01s, a 192-byte record beside each photo). It is served
        // as the directory's own stream, `<dir>:l01_directory_data`, so it is
        // examined like any file; it is not decoded.
        let mut directory_stream: Option<Artifact> = None;
        if is_directory && facts.media_data_size.is_some_and(|n| n > 0) {
            match (facts.size, facts.media_data_size) {
                (Some(sz), Some(stored)) if sz > 0 && stored == sz => {
                    directory_data_streams += 1;
                    m["l01_directory_data_stream"] =
                        json!(format!("{full_path}:l01_directory_data"));
                    directory_stream = Some(directory_data_artifact(
                        artifact,
                        path,
                        opened,
                        ordinal,
                        entry,
                        &entry_name,
                        &full_path,
                        m["parent_path"].clone(),
                        sz,
                    ));
                }
                (Some(0), Some(1)) => {
                    // libewf's form for an entry with no content: a recorded
                    // size of 0 must store exactly one byte, which libewf
                    // does not serve as content (`libewf_file_entry.c`).
                    // HUNT-250: the byte is read by the walk and recorded as
                    // a value. Whether it is stored for this entry alone is
                    // checked here against every walked entry's stored span,
                    // and said only when the check holds; what EnCase means
                    // by the byte is not established.
                    directory_placeholders += 1;
                    m["l01_directory_placeholder_byte"] = json!(true);
                    let (span, where_stored) = if !facts.is_placeholder_form() {
                        ("no_usable_offset", "")
                    } else if walk.is_incomplete() {
                        (
                            "not_checked_walk_incomplete",
                            " Whether any other entry's stored data covers it was not \
                             checked, because the walk is incomplete.",
                        )
                    } else if !span_checked {
                        (
                            "not_checked_span_unknown",
                            " Whether any other entry's stored data covers it was not \
                             checked: libewf would not give where some entry's data is \
                             stored (see stored_spans_unknown in the inventory), and \
                             that data could cover it.",
                        )
                    } else if spans.shares[ordinal] {
                        directory_placeholders_shared += 1;
                        (
                            "shared",
                            " It lies inside another entry's stored data, so it is not \
                             held by this entry by itself.",
                        )
                    } else {
                        directory_placeholders_alone += 1;
                        (
                            "alone",
                            " It lies at l01_media_data_offset, and no other entry's \
                             stored data, nor any sparse entry's read at its duplicate \
                             data offset, covers that byte.",
                        )
                    };
                    m["l01_directory_placeholder_byte_span"] = json!(span);
                    const FORM: &str = "This directory records no size and stores one \
                                        byte, the form libewf reads as an entry with no \
                                        content.";
                    let detail = match facts.placeholder_byte {
                        Some(byte) => {
                            directory_placeholder_values += 1;
                            m["l01_directory_placeholder_value"] = json!(byte);
                            format!(
                                "{FORM} The byte is 0x{byte:02X} (in \
                                 l01_directory_placeholder_value).{where_stored} Its \
                                 meaning is not established, and it is recorded, not \
                                 served, because it is not content"
                            )
                        }
                        None if !facts.is_placeholder_form() => format!(
                            "{FORM} The byte was not read: no usable media offset is \
                             recorded. Its meaning is not established in any case, and \
                             it is not served, because it is not content"
                        ),
                        None => format!(
                            "{FORM} The byte could not be read (see \
                             l01_field_errors).{where_stored} Its meaning is not \
                             established in any case, and it is not served, because it \
                             is not content"
                        ),
                    };
                    m["l01_directory_data_detail"] = json!(detail);
                }
                _ => {
                    directory_data_unserved += 1;
                    m["l01_directory_data_not_served"] = json!(true);
                    m["l01_directory_data_detail"] = json!(format!(
                        "This directory stores {} byte(s) against a recorded size of {}; \
                         libewf serves an entry's data only when the two agree, so the \
                         bytes are not served",
                        facts.media_data_size.unwrap_or(0),
                        facts
                            .size
                            .map_or_else(|| "none".to_string(), |n| n.to_string())
                    ));
                }
            }
        }

        position_of.push(entries.len());
        entries.push(
            Artifact::new(artifact.case_id, ArtifactType::FileEntry, data, m)
                .with_parent(artifact.id),
        );
        if let Some(stream) = directory_stream {
            entries.push(stream);
        }
    }
    for (at, ordinal) in sparse_entries {
        settle_sparse_entry(&mut entries, at, ordinal, walk, &position_of);
    }
    seance_core::data_source::attach_sibling_bundles(&mut entries);

    let limits = walk.limits.unwrap_or_default();
    let mut inv = json!({
        "type": "LogicalEvidenceInventory",
        "subtype": "ewf_logical_inventory",
        "name": format!(
            "{name}: logical evidence file, {} entries",
            entries.len() - directory_data_streams
        ),
        "short_desc": "EWF logical evidence file (L01): its entry tree, walked through libewf",
        "container": "ewf_logical",
        "container_path": path,
        "module": "container.e01_reader",
        "entries_published": entries.len() - directory_data_streams,
        "root_present": walk.root_present,
        "entry_cap": limits.max_entries,
        "depth_cap": limits.max_depth,
        "entry_cap_reached": walk.entry_cap_reached,
        "depth_cap_reached": walk.depth_cap_reached,
        "entries_not_walked": walk.entries_not_walked,
        "walk_errors": walk.errors.iter().take(100).collect::<Vec<_>>(),
        "walk_error_count": walk.errors.len(),
        "unreadable_names": unreadable_names,
        "entries_with_field_errors": entries_with_field_errors,
        "directory_data_streams_published": directory_data_streams,
        "directory_placeholder_bytes_not_served": directory_placeholders,
        "directory_placeholder_values_recorded": directory_placeholder_values,
        "directory_placeholder_bytes_alone": directory_placeholders_alone,
        "directory_placeholder_bytes_in_shared_span": directory_placeholders_shared,
        "directory_placeholder_spans_checked": span_checked,
        "stored_spans_unknown": spans.unknown,
        "walk_incomplete": walk.is_incomplete(),
        "media_size": opened.media_size,
        "e01_metadata": opened.metadata,
    });
    hoist_segment_stamps(&opened.metadata, &mut inv);
    publish_open_mode(opened.isolated, &mut inv);
    if walk.is_incomplete() {
        let mut why = Vec::new();
        if walk.entry_cap_reached {
            why.push(format!(
                "the walk stopped at its ceiling of {} entries",
                limits.max_entries
            ));
        }
        if walk.depth_cap_reached {
            why.push(format!(
                "entries below level {} were not descended into",
                limits.max_depth
            ));
        }
        if !walk.errors.is_empty() {
            why.push(format!(
                "libewf failed {} time(s) to hand over an entry or its sub-entry count",
                walk.errors.len()
            ));
        }
        let detail = format!(
            "Not every entry this logical evidence file lists was published: {}. At least {} \
             listed entries were not walked, and anything below them is unexamined.",
            why.join("; "),
            walk.entries_not_walked
        );
        inv["content_incomplete"] = json!(true);
        inv["content_incomplete_reason"] =
            json!(if walk.entry_cap_reached || walk.depth_cap_reached {
                seance_core::io::IncompleteReason::CapReached.as_str()
            } else {
                seance_core::io::IncompleteReason::UnresolvedStructure.as_str()
            });
        inv["content_incomplete_detail"] = json!(detail);
    } else if !walk.root_present {
        inv["detail"] = json!(
            "libewf reports no root entry: this logical evidence file's entry table lists \
             nothing, so there are no files to publish"
        );
    }
    if directory_data_streams > 0 {
        inv["directory_data_detail"] = json!(format!(
            "{directory_data_streams} directory entries carry data of their own in this L01 \
             (EnCase keeps records there; on a phone acquisition, a record beside each file). \
             Each is served as the directory's own stream, `<directory>:l01_directory_data`, \
             so it is examined like any file; its layout is not established, so it is not \
             decoded."
        ));
    }
    if directory_data_unserved > 0 {
        inv["directories_with_data_not_served"] = json!(directory_data_unserved);
    }
    info!(
        "L01 {}: {} entries published (incomplete: {})",
        path,
        entries.len(),
        walk.is_incomplete()
    );
    out.push(
        Artifact::new(artifact.case_id, ArtifactType::ParsedRecord, None, inv)
            .with_parent(artifact.id)
            .with_subtype("ewf_logical_inventory"),
    );
    out.extend(entries);
    out
}

/// The largest sparse entry whose served bytes are hashed at ingest to check
/// them against the MD5 the L01 stores for it (`HUNT-247`). Real sparse
/// entries are small (12,288 bytes on the NGDC phone L01s); a larger one is
/// served stamped `unvalidated` rather than read whole during the walk.
pub const MAX_SPARSE_VERIFY_BYTES: u64 = 64 * 1024 * 1024;

/// The `FileEntry` for the data EnCase stores against a directory entry
/// (`HUNT-246`): the directory's own stream, `<directory>:l01_directory_data`,
/// read through libewf exactly as a file entry's bytes are. Published beside
/// the directory, not inside it, and never decoded.
#[allow(clippy::too_many_arguments)]
fn directory_data_artifact(
    artifact: &Artifact,
    container_path: &str,
    opened: &isolated::OpenedL01,
    ordinal: usize,
    entry: &logical::LogicalEntry,
    entry_name: &str,
    full_path: &str,
    parent_path: serde_json::Value,
    size: u64,
) -> Artifact {
    let m = json!({
        "name": format!("{entry_name}:l01_directory_data"),
        "path": format!("{full_path}:l01_directory_data"),
        "parent_path": parent_path,
        "size": size,
        "is_directory": false,
        "container": "ewf_logical",
        "container_path": container_path,
        "l01_record_kind": "directory_data",
        "l01_directory_data_of": full_path,
        "l01_entry_ordinal": ordinal,
        "l01_index_path": entry.index_path,
        "l01_media_data_offset": entry.facts.media_data_offset,
        "l01_media_data_size": entry.facts.media_data_size,
        "l01_directory_data_decoded": false,
        "l01_directory_data_detail":
            "Data EnCase stores against the directory entry itself, served as libewf reads \
             it for that entry. Its layout is not established from an independent source, so \
             it is published as bytes and not decoded: nothing in it is presented as a time, \
             a name or a size.",
    });
    let data: std::sync::Arc<dyn DataSource> =
        std::sync::Arc::new(seance_core::data_source::CachingDataSource::new(
            std::sync::Arc::new(logical::LogicalEntrySource::new(
                opened.backend.clone(),
                ordinal as u32,
                size,
            )),
            64 * 1024,
            4 * 1024 * 1024,
        ));
    Artifact::new(artifact.case_id, ArtifactType::FileEntry, Some(data), m).with_parent(artifact.id)
}

/// Read a whole data source of at most [`MAX_SPARSE_VERIFY_BYTES`].
fn read_whole(src: &dyn DataSource) -> std::io::Result<Vec<u8>> {
    let size = usize::try_from(src.size()).map_err(std::io::Error::other)?;
    let mut out = vec![0u8; size];
    let mut done = 0usize;
    while done < size {
        match src.read_at(done as u64, &mut out[done..])? {
            0 => break,
            n => done += n,
        }
    }
    out.truncate(done);
    Ok(out)
}

/// State what a sparse L01 entry is served, and check it (`HUNT-247`).
///
/// libewf's `libewf_file_entry_read_buffer` (20140816, the version this build
/// links) reads a sparse entry in one of two ways: when the entry names a
/// duplicate data offset (`du` in the entry table), the recorded size is read
/// from the media stream at that offset — EnCase stored the content once, for
/// another entry with the same bytes; otherwise the one stored byte is
/// repeated to the recorded size. Which way applied is stated, the entry the
/// duplicate offset points at is named, and where the L01 stores an MD5 for
/// the sparse entry the bytes served are hashed and compared with it. Only a
/// match lifts the `unvalidated` stamp.
fn settle_sparse_entry(
    entries: &mut [Artifact],
    at: usize,
    ordinal: usize,
    walk: &logical::LogicalWalk,
    position_of: &[usize],
) {
    let facts = &walk.entries[ordinal].facts;
    let stored = facts.media_data_size.unwrap_or(0);
    let size = entries[at].metadata["size"].as_u64();
    let duplicate = facts.duplicate_media_data_offset.filter(|d| *d >= 0);

    let mut how = match duplicate {
        Some(du) => {
            entries[at].metadata["l01_content_source"] = json!("duplicate_data_offset");
            let target = walk.entries.iter().enumerate().find(|(j, e)| {
                *j != ordinal
                    && e.facts.entry_type == Some(logical::ENTRY_TYPE_FILE)
                    && e.facts.media_data_offset == Some(du)
                    && e.facts
                        .flags
                        .is_none_or(|f| f & logical::ENTRY_FLAG_SPARSE_DATA == 0)
            });
            match target.and_then(|(j, _)| position_of.get(j).map(|p| (j, *p))) {
                Some((j, p)) => {
                    let target_path = entries[p].metadata["path"].clone();
                    entries[at].metadata["l01_duplicate_of_path"] = target_path.clone();
                    entries[at].metadata["l01_duplicate_of_ordinal"] = json!(j);
                    format!(
                        "The L01 flags this entry's data as sparse (it stores {stored} byte(s)) \
                         and names a duplicate data offset, {du}: libewf reads the entry's \
                         content from the media stream there. That is the media offset of \
                         the entry {}, whose content EnCase stored once for both",
                        target_path.as_str().unwrap_or("[unnamed]")
                    )
                }
                None => format!(
                    "The L01 flags this entry's data as sparse (it stores {stored} byte(s)) and \
                     names a duplicate data offset, {du}: libewf reads the entry's content from \
                     the media stream there. No other file entry in this L01 has its data at \
                     that offset, so whose content it is was not established"
                ),
            }
        }
        None => {
            entries[at].metadata["l01_content_source"] = json!("sparse_one_byte_repeated");
            format!(
                "The L01 flags this entry's data as sparse (it stores {stored} byte(s)) and names \
                 no duplicate data offset: libewf serves the one stored byte repeated to the \
                 recorded size of {}",
                size.unwrap_or(0)
            )
        }
    };

    let stored_md5 = facts.md5.clone();
    let check = match (&stored_md5, entries[at].data.clone(), size) {
        (Some(md5), Some(src), Some(n)) if n <= MAX_SPARSE_VERIFY_BYTES => {
            match read_whole(src.as_ref()) {
                Ok(bytes) if bytes.len() as u64 == n => {
                    let got = seance_core::hashing::compute_hashes(&bytes).md5;
                    if got.eq_ignore_ascii_case(md5) {
                        how.push_str(
                            ". The bytes served hash to the MD5 the L01 stores for this entry",
                        );
                        "stored_md5_matches"
                    } else {
                        how.push_str(&format!(
                            ". The bytes served hash to {got}, not to the MD5 the L01 stores for \
                             this entry ({md5}), so they are not established as its content"
                        ));
                        "stored_md5_differs"
                    }
                }
                Ok(bytes) => {
                    how.push_str(&format!(
                        ". libewf served {} of {n} bytes, so they were not checked against the \
                         stored MD5",
                        bytes.len()
                    ));
                    "not_checked"
                }
                Err(e) => {
                    how.push_str(&format!(
                        ". Reading them to check against the stored MD5 failed ({e})"
                    ));
                    "not_checked"
                }
            }
        }
        (None, _, _) => {
            how.push_str(". The L01 stores no MD5 for this entry, so the bytes were not checked");
            "no_stored_md5"
        }
        _ => {
            how.push_str(&format!(
                ". The entry is larger than {MAX_SPARSE_VERIFY_BYTES} bytes or has no data \
                 source, so the bytes were not checked against the stored MD5"
            ));
            "not_checked"
        }
    };
    let m = &mut entries[at].metadata;
    m["l01_duplicate_content_check"] = json!(check);
    m["l01_content_source_detail"] = json!(format!("{how}."));
    match check {
        "stored_md5_matches" => {}
        "stored_md5_differs" => {
            m["content_incomplete"] = json!(true);
            m["content_incomplete_reason"] =
                json!(seance_core::io::IncompleteReason::UnresolvedStructure.as_str());
            m["content_incomplete_detail"] = json!(format!("{how}."));
        }
        _ => {
            m["content_incomplete"] = json!(true);
            m["content_incomplete_reason"] =
                json!(seance_core::io::IncompleteReason::Unvalidated.as_str());
            m["content_incomplete_detail"] = json!(format!("{how}."));
        }
    }
}

/// Open the data EnCase stores against the directory entry at `index_path`
/// (`HUNT-246`), for the content resolver: the `<dir>:l01_directory_data`
/// stream [`E01ContainerModule`] published. Refuses a file entry, and a
/// directory whose stored data does not match its recorded size.
pub fn open_logical_directory_data(
    path: &str,
    index_path: &[u32],
) -> Result<std::sync::Arc<dyn DataSource>> {
    let opened = isolated::open_l01(path)?;
    let (ordinal, entry) = opened
        .walk
        .entries
        .iter()
        .enumerate()
        .find(|(_, e)| e.index_path == index_path)
        .ok_or_else(|| anyhow!("no entry at {index_path:?} in {path}"))?;
    if entry.facts.entry_type != Some(logical::ENTRY_TYPE_DIRECTORY) {
        return Err(anyhow!("entry {index_path:?} in {path} is not a directory"));
    }
    let size = match (entry.facts.size, entry.facts.media_data_size) {
        (Some(s), Some(m)) if s > 0 && s == m => s,
        _ => {
            return Err(anyhow!(
                "directory {index_path:?} in {path} has no data libewf serves"
            ))
        }
    };
    Ok(std::sync::Arc::new(logical::LogicalEntrySource::new(
        opened.backend.clone(),
        ordinal as u32,
        size,
    )))
}

/// Open the one entry of the logical evidence file at `path` whose position in
/// the tree is `index_path`, as a data source over its bytes. For the content
/// resolver, which rebuilds an entry's source from its stored metadata: the
/// tree is walked afresh (in the helper by default) and the entry found by its
/// index path, never by its name, which need not be unique.
pub fn open_logical_entry(
    path: &str,
    index_path: &[u32],
) -> Result<std::sync::Arc<dyn DataSource>> {
    let opened = isolated::open_l01(path)?;
    let (ordinal, entry) = opened
        .walk
        .entries
        .iter()
        .enumerate()
        .find(|(_, e)| e.index_path == index_path)
        .ok_or_else(|| anyhow!("no entry at {index_path:?} in {path}"))?;
    if entry.facts.entry_type == Some(logical::ENTRY_TYPE_DIRECTORY) {
        return Err(anyhow!("entry {index_path:?} in {path} is a directory"));
    }
    let size = entry
        .facts
        .size
        .or(entry.facts.media_data_size)
        .ok_or_else(|| anyhow!("entry {index_path:?} in {path} has no size libewf will give"))?;
    Ok(std::sync::Arc::new(logical::LogicalEntrySource::new(
        opened.backend.clone(),
        ordinal as u32,
        size,
    )))
}

/// Returns true if `name` ends with a recognized EWF segment extension.
///
/// EWF (Expert Witness Format) uses a three-character extension to label each
/// segment of a multi-file image:
///
/// * `.E01`-`.E99`, then `.EAA`-`.EZZ` — standard segments (physical image)
/// * `.S01`-`.S99`, `.SAA`-`.SZZ` — split (compressed) segments
/// * `.L01`-`.L99`, `.LAA`-`.LZZ` — logical evidence files
///
/// The digit form (`.E01`) accepts mixed case (`.E01` and `.e01` both match)
/// since case-insensitive filesystems are common in practice. The letter
/// continuation form (`.EAA`) requires uppercase, because real EWF tooling
/// produces uppercase and accepting `.eaa` would falsely match files like
/// `.exe`, `.eml`, `.epub`, `.css`.
///
/// All recognized extensions are pure ASCII, so any non-ASCII filename
/// extension returns false (and never panics on multi-byte UTF-8 chars).
fn is_ewf_segment_extension(name: &str) -> bool {
    let ext = match name.rsplit_once('.') {
        Some((_, e)) => e,
        None => return false,
    };
    // EWF extensions are exactly 3 ASCII characters. If the byte length or
    // char count is anything else — or if any byte is non-ASCII — bail out.
    // (Comparing byte length alone would let a single 3-byte UTF-8 char like
    // '€' slip through and panic the char iterator below.)
    let bytes = ext.as_bytes();
    if bytes.len() != 3 || !ext.is_ascii() {
        return false;
    }
    let c1 = bytes[0];
    let c2 = bytes[1];
    let c3 = bytes[2];
    // First char (prefix): one of E/S/L, either case.
    let prefix_ok = matches!(c1, b'e' | b'E' | b's' | b'S' | b'l' | b'L');
    if !prefix_ok {
        return false;
    }
    // Numbered form: two ASCII digits, and not `00` — libewf numbers segments
    // from one, and `seance_core::ingestion::ewf_segment_ordinal` refuses
    // `.E00` on exactly that ground. Two gates that disagree about what a
    // segment is will disagree about what a set is.
    if c2.is_ascii_digit() && c3.is_ascii_digit() {
        return !(c2 == b'0' && c3 == b'0');
    }
    // Letter continuation form: two uppercase ASCII letters (avoids `.exe`/`.eml`).
    if c2.is_ascii_uppercase() && c3.is_ascii_uppercase() {
        return true;
    }
    false
}

impl ForensicsModule for E01ContainerModule {
    fn id(&self) -> &str {
        "container.e01_reader"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::Container]
    }

    fn input_capability(&self) -> InputCapability {
        InputCapability::FilePath
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        // Fast path: check subtype first
        if let Some(subtype) = artifact.subtype() {
            if subtype != "e01" && subtype != "ewf" {
                return Ok(Vec::new()); // Early exit optimization
            }
        }

        let name = artifact
            .metadata
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or_default();

        // Fallback: Check for E01 / multi-segment EWF file extension if no subtype.
        // EWF segments: `.E01`-`.E99`, `.EAA`-`.EZZ`, plus `.S01-.SZZ` (split),
        // `.L01-.LZZ` (logical). See `is_ewf_segment_extension` for exact rules.
        if artifact.subtype().is_none() && !is_ewf_segment_extension(name) {
            return Ok(Vec::new());
        }

        info!("E01ContainerModule processing: {}", name);

        // Get the file path
        let path = artifact
            .metadata
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                ModuleError::InvalidInputFormat("E01 module requires file path".to_string())
            })?;

        // What the file's own bytes say it is. A logical evidence file (`LVF`)
        // holds files, not an image of a device: libewf will open it and serve
        // a media stream, and publishing that as raw evidence would hand EWF
        // structure to the partition, file-system and carving modules as
        // device content. Nothing here or downstream enumerates what an L01
        // holds, so the honest answer is a refusal that says which of the two
        // it is and what was not done with it.
        //
        // A file whose family cannot be read is not a file that is not EWF:
        // that error is left to libewf, which is about to try the same file
        // and report on it.
        match ewf_family(path) {
            Ok(Some(EwfFamily::Logical)) => {
                // A logical evidence file holds files, not an image of a
                // device: its media stream is EnCase's packing of those files'
                // data and is never published as raw evidence, which would hand
                // EWF structure to the partition, file-system and carving
                // modules as device content. Its entry tree is walked instead
                // and every entry published as a file (HUNT-144).
                return Ok(process_logical(artifact, name, path));
            }
            Ok(_) => {}
            Err(e) => debug!("could not read the EWF family of {}: {}", path, e),
        }

        // Open E01 image. By default this runs libewf in an isolated helper
        // subprocess (isolated::open_e01) so a crash on a hostile image can't
        // take down this process; it falls back to in-process only when
        // isolation is disabled or the helper binary is absent.
        let opened = isolated::open_e01(path)
            .map_err(|e| ModuleError::ParsingError(format!("Failed to open E01 image: {}", e)))?;
        let e01_metadata = opened.metadata.clone();
        let size = opened.size;
        let isolated_open = opened.isolated;

        // The container-embedded acquisition hashes are hashes of the DECODED
        // MEDIA, so they belong on this extracted image (not the container file
        // ingested above, whose acquisition_* hashes the container bytes).
        // Surfaced at the top level so Verify Integrity can recompute the media
        // hash and check it against this baseline (evaluate_integrity reads
        // stored_md5/stored_sha1).
        let stored_md5 = e01_metadata.get("stored_md5").cloned();
        let stored_sha1 = e01_metadata.get("stored_sha1").cloned();
        // The segment-set completeness stamps have to be hoisted for the same
        // reason: every consumer of the incompleteness pair reads an artifact's
        // top-level metadata, so a flag left inside `e01_metadata` is written
        // and never rendered (B7-030).
        let segment_stamps = e01_metadata.clone();
        // Create RawEvidence artifact with E01DataSource
        let mut metadata = json!({
            "name": extracted_name(name, path),
            "size": size,
            "subtype": "raw",  // Generic raw disk image
            "container": "e01",
            "container_path": path,
            "e01_metadata": e01_metadata,
        });
        if let Some(md5) = stored_md5 {
            metadata["stored_md5"] = md5;
        }
        if let Some(sha1) = stored_sha1 {
            metadata["stored_sha1"] = sha1;
        }
        hoist_segment_stamps(&segment_stamps, &mut metadata);
        publish_open_mode(isolated_open, &mut metadata);

        let evidence_artifact = Artifact::new(
            artifact.case_id,
            ArtifactType::RawEvidence,
            Some(opened.source),
            metadata,
        )
        .with_parent(artifact.id);

        info!("E01 container extracted: {} bytes raw disk image", size);

        Ok(vec![evidence_artifact])
    }
}

#[cfg(test)]
mod tests {
    //! Surface tests for `E01ContainerModule`.
    //!
    //! These tests exercise the routing layer of `process()` — subtype check,
    //! extension fallback, metadata validation — without invoking libewf, since
    //! that needs a real `.e01` fixture file. The FFI parsing path is covered
    //! by integration tests in `seance_tests` when an E01 image is provided.
    use super::*;
    use uuid::Uuid;

    fn make_artifact(name: &str, subtype: Option<&str>, path: Option<&str>) -> Artifact {
        let mut meta = json!({ "name": name });
        if let Some(s) = subtype {
            meta["subtype"] = json!(s);
        }
        if let Some(p) = path {
            meta["path"] = json!(p);
        }
        Artifact::new(Uuid::new_v4(), ArtifactType::Container, None, meta)
    }

    // --- HUNT-142: acquisition provenance name mappings -------------------

    #[test]
    fn ewf_format_names_the_values_libewf_hands_back() {
        // Values are LIBEWF_FORMAT_* from /usr/include/libewf/definitions.h
        // (the enum this crate's bindgen allowlist does not surface by name,
        // since it has no libewf_/LIBEWF_ prefix on the enumerators as bindgen
        // sees them through this build's allowlist_var("LIBEWF_.*") — the
        // values are transcribed by hand from that header and must be kept in
        // step with it).
        assert_eq!(ewf_format_name(0x00), "unknown");
        assert_eq!(ewf_format_name(0x06), "EnCase6");
        assert_eq!(ewf_format_name(0x07), "EnCase7");
        assert_eq!(ewf_format_name(0x0e), "SMART");
        assert_eq!(ewf_format_name(0x0f), "FTK Imager");
        assert_eq!(ewf_format_name(0x10), "logical EnCase5");
        assert_eq!(ewf_format_name(0x70), "EWF");
        assert_eq!(ewf_format_name(0x71), "EWFX");
        // An EnCase version this table does not name yet must say so, not
        // silently claim "unknown" (which is itself a real, distinct value,
        // 0x00) or panic.
        assert_eq!(ewf_format_name(0xAB), "unrecognised (0xab)");
    }

    #[test]
    fn compression_level_names_the_values_libewf_hands_back() {
        // A code-review pass on 2026-09-18 caught this crate confusing two
        // separate libewf enums: `libewf_handle_get_compression_values`'s
        // out-param is literally named `compression_level` in libewf's own
        // header and is a LIBEWF_COMPRESSION_LEVELS value (DEFAULT=-1,
        // NONE=0, FAST=1, BEST=2) -- there is no `get_compression_method`
        // accessor in this build's bindings at all. The crate previously fed
        // this value into a function named `compression_method_name` mapping
        // 0/1/2 to "none"/"deflate"/"bzip2" (the DIFFERENT
        // LIBEWF_COMPRESSION_METHODS enum), so an image acquired at level
        // BEST (2) was reported as "bzip2" and level FAST (1) as "deflate" --
        // wrong regardless of what codec was actually used, since standard
        // EWF only ever uses zlib/DEFLATE (bzip2 needs EWF2/Ex01, which this
        // value says nothing about).
        assert_eq!(compression_level_name(-1), "default");
        assert_eq!(compression_level_name(0), "none");
        assert_eq!(compression_level_name(1), "fast");
        assert_eq!(compression_level_name(2), "best");
        assert_eq!(compression_level_name(9), "unrecognised (9)");
    }

    // --- HUNT-143: which of the three open paths ran ------------------------

    /// The parent has three ways to end up with an opened image, and the
    /// artifact must say which: the isolated helper subprocess (the default),
    /// in-process because isolation was explicitly turned off, or in-process
    /// because the helper binary could not be found. `OpenedE01::isolated`
    /// already tracks the isolated/not-isolated split but was read only by a
    /// test; nothing published it, so a custody fact `open_e01` already knows
    /// never reached the case.
    #[test]
    fn the_open_mode_is_published_not_just_known_internally() {
        let mut metadata = json!({});
        publish_open_mode(true, &mut metadata);
        assert_eq!(metadata["e01_open_mode"], json!("isolated_helper"));

        let mut metadata = json!({});
        publish_open_mode(false, &mut metadata);
        assert_eq!(metadata["e01_open_mode"], json!("in_process"));
    }

    #[test]
    fn module_identity() {
        let m = E01ContainerModule;
        assert_eq!(m.id(), "container.e01_reader");
        assert!(!m.version().is_empty());
        assert_eq!(m.subscribes_to(), vec![ArtifactType::Container]);
        assert_eq!(m.input_capability(), InputCapability::FilePath);
    }

    #[test]
    fn non_e01_subtype_short_circuits() {
        // A Container artifact tagged as e.g. "aff4" must not be processed.
        let art = make_artifact("evidence.aff4", Some("aff4"), Some("/tmp/x.aff4"));
        let out = E01ContainerModule.process(&art).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn ewf_subtype_alias_is_accepted() {
        // "ewf" should reach the path-extraction step (and fail there with
        // InvalidInputFormat since we omit the path), proving it passed the
        // subtype gate.
        let art = make_artifact("evidence.e01", Some("ewf"), None);
        match E01ContainerModule.process(&art) {
            Err(ModuleError::InvalidInputFormat(_)) => {}
            other => panic!(
                "expected InvalidInputFormat (path missing), got {:?}",
                other
            ),
        }
    }

    #[test]
    fn e01_subtype_is_accepted() {
        let art = make_artifact("evidence.e01", Some("e01"), None);
        match E01ContainerModule.process(&art) {
            Err(ModuleError::InvalidInputFormat(_)) => {}
            other => panic!(
                "expected InvalidInputFormat (path missing), got {:?}",
                other
            ),
        }
    }

    #[test]
    fn no_subtype_non_e01_filename_short_circuits() {
        let art = make_artifact("random.bin", None, Some("/tmp/random.bin"));
        let out = E01ContainerModule.process(&art).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn no_subtype_e01_filename_proceeds_to_path_check() {
        let art = make_artifact("evidence.e01", None, None);
        match E01ContainerModule.process(&art) {
            Err(ModuleError::InvalidInputFormat(_)) => {}
            other => panic!(
                "expected InvalidInputFormat (path missing), got {:?}",
                other
            ),
        }
    }

    // -- is_ewf_segment_extension regression coverage ------------------------
    //
    // This helper was added to fix a pre-existing bug where the no-subtype
    // fallback used `name.contains(".e")`, which matched `.exe`, `.eml`, etc.

    #[test]
    fn ewf_segment_recognized_for_standard_e_numbered() {
        for n in 1..=99u32 {
            let name = format!("img.E{:02}", n);
            assert!(is_ewf_segment_extension(&name), "{} should match", name);
            // Case-insensitive.
            let lower = name.to_lowercase();
            assert!(is_ewf_segment_extension(&lower));
        }
    }

    #[test]
    fn ewf_segment_recognized_for_letter_continuation() {
        assert!(is_ewf_segment_extension("img.EAA"));
        assert!(is_ewf_segment_extension("img.EZZ"));
        // Note: lowercase letter-continuation (e.g. "img.eaa") is intentionally
        // NOT matched — it would collide with `.exe`, `.eml`, `.epub`, etc.
        // Real EWF tooling produces uppercase; users would need to rename to
        // uppercase or set subtype="e01" explicitly to ingest them.
        assert!(!is_ewf_segment_extension("img.eaa"));
    }

    #[test]
    fn ewf_segment_recognized_for_split_and_logical() {
        // Split (compressed) and logical (.S/.L) prefixes are also valid EWF.
        assert!(is_ewf_segment_extension("img.S01"));
        assert!(is_ewf_segment_extension("img.SZZ"));
        assert!(is_ewf_segment_extension("img.L01"));
        assert!(is_ewf_segment_extension("img.LAA"));
    }

    #[test]
    fn ewf_segment_does_not_panic_on_utf8_extension() {
        // Regression: byte length check alone would allow a single 3-byte
        // UTF-8 char to slip through and crash the char-iterator approach.
        // None of these should be recognized as EWF segments, and none should panic.
        assert!(!is_ewf_segment_extension("evidence.€")); // 3 bytes, 1 char
        assert!(!is_ewf_segment_extension("img.中日韩")); // 9 bytes, 3 chars
        assert!(!is_ewf_segment_extension("a.ñℓ¶")); // mixed widths
        assert!(!is_ewf_segment_extension("a.日")); // 3 bytes, 1 char
                                                    // Extension starts with an ASCII letter but follows with multi-byte —
                                                    // would have been the worst case for the old chars-based path.
        assert!(!is_ewf_segment_extension("a.E€"));
    }

    #[test]
    fn ewf_segment_rejects_common_false_positives() {
        // The original bug — these all incorrectly matched `.contains(".e")`.
        assert!(!is_ewf_segment_extension("notepad.exe"));
        assert!(!is_ewf_segment_extension("message.eml"));
        assert!(!is_ewf_segment_extension("book.epub"));
        assert!(!is_ewf_segment_extension("contact.email"));
        // Also reject mixed digit+letter (not part of the EWF spec).
        assert!(!is_ewf_segment_extension("img.E1A"));
        assert!(!is_ewf_segment_extension("img.S2Z"));
        // Reject other prefixes.
        assert!(!is_ewf_segment_extension("img.X01"));
        // Reject 2- and 4-char extensions.
        assert!(!is_ewf_segment_extension("img.E1"));
        assert!(!is_ewf_segment_extension("img.E001"));
        // Reject names with no extension.
        assert!(!is_ewf_segment_extension("evidence"));
        assert!(!is_ewf_segment_extension(""));
    }

    #[test]
    fn process_correctly_rejects_exe_files() {
        // Regression: `process()` must not pretend `.exe` is an EWF segment.
        let art = make_artifact("notepad.exe", None, Some("/tmp/notepad.exe"));
        let out = E01ContainerModule.process(&art).unwrap();
        assert!(
            out.is_empty(),
            ".exe files must not enter the E01 parsing path"
        );
    }

    #[test]
    fn process_correctly_rejects_eml_files() {
        let art = make_artifact("message.eml", None, Some("/tmp/message.eml"));
        let out = E01ContainerModule.process(&art).unwrap();
        assert!(
            out.is_empty(),
            ".eml files must not enter the E01 parsing path"
        );
    }

    #[test]
    fn process_accepts_multi_segment_e02() {
        // A `.E02` segment of a multi-file image — no subtype, fallback path.
        // Should pass the extension gate and reach the path-existence check.
        let art = make_artifact("img.E02", None, None);
        match E01ContainerModule.process(&art) {
            Err(ModuleError::InvalidInputFormat(_)) => {}
            other => panic!(
                "expected InvalidInputFormat (path missing), got {:?}",
                other
            ),
        }
    }

    #[test]
    fn missing_path_with_e01_subtype_is_invalid_input() {
        let art = make_artifact("evidence.e01", Some("e01"), None);
        match E01ContainerModule.process(&art) {
            Err(ModuleError::InvalidInputFormat(msg)) => {
                assert!(
                    msg.contains("file path"),
                    "msg should mention file path: {}",
                    msg
                );
            }
            other => panic!("expected InvalidInputFormat, got {:?}", other),
        }
    }

    #[test]
    fn nonexistent_path_surfaces_parsing_error() {
        // Subtype + path both set; libewf will fail to open this nonexistent
        // file and the module must translate that into ParsingError, NOT panic.
        let art = make_artifact(
            "evidence.e01",
            Some("e01"),
            Some("/tmp/seance_e01_definitely_not_there_xyz.e01"),
        );
        match E01ContainerModule.process(&art) {
            Err(ModuleError::ParsingError(_)) => {}
            other => panic!("expected ParsingError, got {:?}", other),
        }
    }

    #[test]
    fn e01_datasource_open_on_nonexistent_path_returns_error() {
        let result = E01DataSource::open("/tmp/seance_e01_xyz_definitely_not_there.e01");
        assert!(result.is_err(), "open should fail for nonexistent path");
    }

    /// B7-030: a segment file named in the set but not statable used to be
    /// dropped from the sum by `filter_map(...ok())`, while `segment_count`
    /// still listed it. The custody figure then understated the size of the
    /// evidence set while presenting as the size of the evidence set.
    #[test]
    fn an_unstatable_segment_leaves_the_set_size_unknown_not_understated() {
        let dir = std::env::temp_dir().join(format!("seance_e01_seg_{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let present = dir.join("case.E01");
        std::fs::write(&present, vec![0u8; 4096]).unwrap();
        let absent = dir.join("case.E02");

        let paths = vec![
            present.to_string_lossy().into_owned(),
            absent.to_string_lossy().into_owned(),
        ];
        let (known, unstatable) = measure_segment_bytes(&paths);
        assert_eq!(known, 4096, "the statable segment still counts");
        assert_eq!(unstatable.len(), 1, "the missing segment must be recorded");
        assert!(unstatable[0].contains("case.E02"));

        let mut metadata = json!({});
        apply_segment_size_metadata(&mut metadata, known, &unstatable);
        assert!(
            metadata["segment_bytes_total"].is_null(),
            "an undetermined total must not render as a smaller, confident number"
        );
        assert_eq!(metadata["segment_bytes_known"], json!(4096));
        assert_eq!(metadata["inventory_incomplete"], json!(true));
        assert_eq!(
            metadata["inventory_incomplete_reason"],
            json!("unresolved_structure")
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The counterweight: with every segment on disk the total is a number and
    /// nothing is flagged.
    #[test]
    fn a_complete_segment_set_reports_a_total_and_no_flag() {
        let dir = std::env::temp_dir().join(format!("seance_e01_seg_ok_{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let a = dir.join("case.E01");
        let b = dir.join("case.E02");
        std::fs::write(&a, vec![0u8; 1000]).unwrap();
        std::fs::write(&b, vec![0u8; 24]).unwrap();

        let paths = vec![
            a.to_string_lossy().into_owned(),
            b.to_string_lossy().into_owned(),
        ];
        let (known, unstatable) = measure_segment_bytes(&paths);
        assert!(unstatable.is_empty());

        let mut metadata = json!({});
        apply_segment_size_metadata(&mut metadata, known, &unstatable);
        assert_eq!(metadata["segment_bytes_total"], json!(1024));
        assert!(metadata.get("inventory_incomplete").is_none());
        assert!(metadata.get("segments_unstatable").is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// B7-030, second half: the stamps are written into the nested
    /// `e01_metadata` blob, and every consumer of the incompleteness pair reads
    /// an artifact's TOP-LEVEL metadata. A flag that only ever lives one level
    /// down is written and never rendered.
    #[test]
    fn the_segment_set_stamps_are_hoisted_onto_the_artifact_itself() {
        let mut e01_metadata = json!({ "media_size": 4096 });
        apply_segment_size_metadata(
            &mut e01_metadata,
            4096,
            &["case.E02: No such file or directory".to_string()],
        );

        let mut metadata = json!({
            "name": "case_extracted",
            "container": "e01",
            "e01_metadata": e01_metadata.clone(),
        });
        hoist_segment_stamps(&e01_metadata, &mut metadata);

        assert_eq!(metadata["inventory_incomplete"], json!(true));
        assert_eq!(
            metadata["inventory_incomplete_reason"],
            json!("unresolved_structure")
        );
        assert_eq!(metadata["segment_bytes_known"], json!(4096));
        assert!(metadata["segments_unstatable"].is_array());
        // The nested copy stays put; nothing that already reads it breaks.
        assert_eq!(
            metadata["e01_metadata"]["inventory_incomplete"],
            json!(true)
        );
    }

    /// The sentence has to land where the examiner-facing reader shows it.
    /// `frontend/src/lib/incompleteness.ts` takes its text from
    /// `<flag>_detail` and reads nothing named `message`, so the explanation
    /// of an unknown set size reached the screen as the bare token
    /// `unresolved_structure`.
    #[test]
    fn the_reason_the_set_size_is_unknown_reaches_the_examiner() {
        let mut e01_metadata = json!({ "media_size": 4096 });
        apply_segment_size_metadata(
            &mut e01_metadata,
            4096,
            &["case.E02: No such file or directory".to_string()],
        );
        let detail = e01_metadata["inventory_incomplete_detail"]
            .as_str()
            .expect("the flag explains itself");
        assert!(detail.contains("total size is unknown"), "{detail}");
        // The older key stays for the consumers already on it.
        assert_eq!(e01_metadata["message"], json!(detail));

        let mut metadata = json!({ "container": "e01" });
        hoist_segment_stamps(&e01_metadata, &mut metadata);
        assert_eq!(metadata["inventory_incomplete_detail"], json!(detail));
    }

    /// The counterweight: a complete set hoists nothing, so a clean image
    /// carries no flag at the level the UI reads.
    #[test]
    fn a_complete_segment_set_hoists_no_flag() {
        let mut e01_metadata = json!({ "media_size": 4096 });
        apply_segment_size_metadata(&mut e01_metadata, 4096, &[]);
        let mut metadata = json!({ "container": "e01" });
        hoist_segment_stamps(&e01_metadata, &mut metadata);
        assert!(metadata.get("inventory_incomplete").is_none());
        assert!(metadata.get("segment_bytes_known").is_none());
    }
    /// Segment numbering starts at one. `seance_core`'s own
    /// `ewf_segment_ordinal` refuses `.E00` for that reason, and this gate
    /// accepted it — so the two halves of the product disagreed about what a
    /// segment set is, and a file called `.E00` entered the parsing path as
    /// segment zero of a set that has none.
    #[test]
    fn a_zero_segment_number_is_not_a_segment() {
        for name in ["img.E00", "img.e00", "img.S00", "img.L00"] {
            assert!(
                !is_ewf_segment_extension(name),
                "{name} must not read as an EWF segment: numbering starts at 1"
            );
        }
        // And the first real segment still does.
        assert!(is_ewf_segment_extension("img.E01"));
    }

    /// A logical evidence file is a container of FILES, not an image of a
    /// device, so it is never published as a raw disk image (HUNT-131); since
    /// HUNT-144 its entry tree is walked instead. One libewf cannot open or
    /// walk — here, a bare signature and zeroes — still yields a refusal that
    /// says so, because an exhibit that produced nothing must never read as an
    /// exhibit that held nothing.
    #[test]
    fn a_logical_evidence_file_libewf_cannot_walk_is_a_refusal_record_not_a_disk_image() {
        let dir = std::env::temp_dir().join(format!("seance_e01_l01_{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("case.L01");
        let mut bytes = b"LVF\x09\x0d\x0a\xff\x00".to_vec();
        bytes.extend_from_slice(&[0u8; 512]);
        std::fs::write(&path, &bytes).unwrap();

        let art = make_artifact("case.L01", None, Some(&path.to_string_lossy()));
        let out = E01ContainerModule
            .process(&art)
            .expect("a refusal is not an error");

        assert_eq!(out.len(), 1, "exactly one record: the refusal");
        assert_eq!(out[0].artifact_type, ArtifactType::ParsedRecord);
        assert!(
            !out.iter()
                .any(|a| a.artifact_type == ArtifactType::RawEvidence),
            "an L01 must not be published as a raw disk image"
        );
        let m = &out[0].metadata;
        assert_eq!(m["type"], json!("ContainerRefusal"));
        assert_eq!(m["container"], json!("ewf_logical"));
        assert_eq!(m["content_incomplete"], json!(true));
        assert_eq!(
            m["content_incomplete_reason"],
            json!("unresolved_structure")
        );
        let detail = m["content_incomplete_detail"].as_str().unwrap_or_default();
        assert!(
            detail.contains("logical"),
            "the refusal must say what the file is: {detail}"
        );
        assert!(
            detail.contains("not"),
            "the refusal must say what was not done: {detail}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The counterweight: the refusal is decided by the file's own signature,
    /// not by its extension, so a physical image named `.L01` — and a segment
    /// whose name says nothing — still reaches libewf.
    #[test]
    fn a_physical_image_named_like_a_logical_one_still_opens() {
        let dir = std::env::temp_dir().join(format!("seance_e01_evf_{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("case.L01");
        let mut bytes = b"EVF\x09\x0d\x0a\xff\x00".to_vec();
        bytes.extend_from_slice(&[0u8; 512]);
        std::fs::write(&path, &bytes).unwrap();

        let art = make_artifact("case.L01", None, Some(&path.to_string_lossy()));
        // libewf will refuse these 520 bytes, which is a parsing error — the
        // point is that it got as far as libewf rather than being refused by
        // family.
        match E01ContainerModule.process(&art) {
            Err(ModuleError::ParsingError(_)) => {}
            other => panic!("expected the open to be attempted, got {other:?}"),
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `ewf_family` answers three different ways, and a file it could not read
    /// is not a file that is not EWF. "Could not look" is never "not there".
    #[test]
    fn the_family_of_a_file_it_cannot_read_is_an_error_not_a_no() {
        let dir = std::env::temp_dir().join(format!("seance_e01_fam_{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let short = dir.join("short.E01");
        std::fs::write(&short, b"EVF").unwrap();

        assert!(
            ewf_family("/tmp/seance_e01_no_such_file_xyz.E01").is_err(),
            "an unreadable file must not answer 'not EWF'"
        );
        // A file too short to hold the signature is readable and is not EWF.
        assert_eq!(ewf_family(&short.to_string_lossy()).unwrap(), None);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The refusal to substitute zeroes for an undecodable chunk is the one
    /// libewf setting this module depends on. Asking for it and discarding the
    /// return code published the refusal as established when libewf may never
    /// have accepted it.
    #[test]
    fn the_zero_chunk_refusal_must_be_established_not_assumed() {
        assert!(zero_substitution_refused(1).is_ok());
        let err = zero_substitution_refused(-1).expect_err("a rejected request must fail the open");
        assert!(
            err.to_string().contains("zero"),
            "the error must name what was refused: {err}"
        );
    }

    /// An artifact with a path and no name used to produce an image called
    /// `_extracted`. The file that was opened is always known, so the name
    /// comes from it.
    #[test]
    fn the_extracted_name_falls_back_to_the_file_that_was_opened() {
        assert_eq!(
            extracted_name("case.E01", "/e/case.E01"),
            "case.E01_extracted"
        );
        assert_eq!(extracted_name("", "/e/case.E01"), "case.E01_extracted");
        assert_eq!(extracted_name("", "/"), "e01_image_extracted");
    }
    // --- HUNT-144: what a walked L01 publishes ------------------------------

    #[derive(Debug)]
    struct FixedBackend;
    impl logical::LogicalBackend for FixedBackend {
        fn read_entry(&self, ordinal: u32, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
            for (i, b) in buf.iter_mut().enumerate() {
                *b = (ordinal as u64 + offset + i as u64) as u8;
            }
            Ok(buf.len())
        }
        fn isolated(&self) -> bool {
            true
        }
    }

    fn entry(
        index_path: Vec<u32>,
        parent: Option<u32>,
        name: &str,
        kind: u8,
        size: u64,
    ) -> logical::LogicalEntry {
        logical::LogicalEntry {
            depth: index_path.len() as u32,
            index_path,
            parent,
            facts: logical::EntryFacts {
                name: Some(name.to_string()),
                entry_type: Some(kind),
                flags: Some(0),
                size: Some(size),
                media_data_size: Some(size),
                ..logical::EntryFacts::default()
            },
            sub_entries: Some(0),
            sub_entries_not_walked: 0,
        }
    }

    fn opened(walk: logical::LogicalWalk) -> isolated::OpenedL01 {
        isolated::OpenedL01 {
            backend: std::sync::Arc::new(FixedBackend),
            walk,
            media_size: 4096,
            metadata: json!({}),
            isolated: true,
        }
    }

    /// Paths are built from the tree, times are published under the L01's
    /// own names and projected onto the timeline's, a stored MD5 becomes the
    /// entry's integrity baseline, directories carry no bytes, and a file's
    /// bytes are served to the size the L01 records. The NGDC corpus records
    /// every time as 0, so this is where a real time is exercised.
    #[test]
    fn a_walked_l01_publishes_paths_times_hashes_and_bytes() {
        let mut file = entry(vec![0, 0], Some(1), "a.txt", b'f', 10);
        file.facts.creation_time = Some(1_342_372_560);
        file.facts.modification_time = Some(1_342_372_561);
        file.facts.access_time = Some(0);
        file.facts.entry_modification_time = Some(1_342_372_562);
        file.facts.md5 = Some("0123456789abcdef0123456789abcdef".into());
        let walk = logical::LogicalWalk {
            root_present: true,
            entries: vec![
                entry(vec![], None, "LogicalEntries", b'd', 0),
                entry(vec![0], Some(0), "Docs", b'd', 0),
                file,
            ],
            limits: Some(logical::WalkLimits::default()),
            ..logical::LogicalWalk::default()
        };
        let parent = make_artifact("x.L01", Some("e01"), Some("/e/x.L01"));
        let out = logical_artifacts(&parent, "x.L01", "/e/x.L01", &opened(walk));
        assert_eq!(out.len(), 4, "an inventory and three entries");
        let inv = &out[0].metadata;
        assert_eq!(inv["type"], json!("LogicalEvidenceInventory"));
        assert_eq!(inv["entries_published"], json!(3));
        assert_eq!(inv["walk_incomplete"], json!(false));
        assert_eq!(inv["e01_open_mode"], json!("isolated_helper"));
        assert!(inv.get("content_incomplete").is_none());

        let dir = &out[2];
        assert_eq!(dir.metadata["path"], json!("/LogicalEntries/Docs"));
        assert_eq!(dir.metadata["is_directory"], json!(true));
        assert!(dir.data.is_none());

        let f = &out[3];
        let m = &f.metadata;
        assert_eq!(m["path"], json!("/LogicalEntries/Docs/a.txt"));
        assert_eq!(m["parent_path"], json!("/LogicalEntries/Docs"));
        assert_eq!(m["l01_index_path"], json!([0, 0]));
        assert_eq!(m["l01_creation_time"], json!(1_342_372_560));
        assert_eq!(m["created"], json!("2012-07-15T17:16:00Z"));
        assert_eq!(m["modified"], json!("2012-07-15T17:16:01Z"));
        assert_eq!(m["changed"], json!("2012-07-15T17:16:02Z"));
        assert_eq!(m["l01_access_time"], json!(0));
        assert!(m.get("accessed").is_none(), "0 is unrecorded, not 1970");
        assert_eq!(m["stored_md5"], json!("0123456789abcdef0123456789abcdef"));
        let src = f.data.as_ref().expect("a file's bytes are served");
        assert_eq!(src.size(), 10);
        let mut buf = [0u8; 32];
        assert_eq!(
            src.read_at(0, &mut buf).unwrap(),
            10,
            "reads end at the recorded size"
        );
        assert_eq!(buf[0], 2, "entry 2's bytes, from the backend, by ordinal");
        assert_eq!(src.read_at(10, &mut buf).unwrap(), 0);
    }

    /// A walk that stopped at a ceiling says so on its inventory, with the
    /// standard incompleteness triple, and a sparse entry is served as
    /// unvalidated rather than as the file.
    #[test]
    fn a_capped_walk_and_a_sparse_entry_are_stated_not_silent() {
        let mut sparse = entry(vec![0], Some(0), "s.db", b'f', 12288);
        sparse.facts.flags = Some(logical::ENTRY_FLAG_SPARSE_DATA);
        sparse.facts.media_data_size = Some(1);
        let mut root = entry(vec![], None, "LogicalEntries", b'd', 0);
        root.sub_entries = Some(5);
        root.sub_entries_not_walked = 4;
        let walk = logical::LogicalWalk {
            root_present: true,
            entries: vec![root, sparse],
            limits: Some(logical::WalkLimits {
                max_entries: 2,
                max_depth: 256,
            }),
            entry_cap_reached: true,
            entries_not_walked: 4,
            ..logical::LogicalWalk::default()
        };
        let parent = make_artifact("x.L01", Some("e01"), Some("/e/x.L01"));
        let out = logical_artifacts(&parent, "x.L01", "/e/x.L01", &opened(walk));
        let inv = &out[0].metadata;
        assert_eq!(inv["walk_incomplete"], json!(true));
        assert_eq!(inv["content_incomplete"], json!(true));
        assert_eq!(inv["content_incomplete_reason"], json!("cap_reached"));
        assert_eq!(inv["entry_cap"], json!(2));
        assert_eq!(inv["entries_not_walked"], json!(4));
        let detail = inv["content_incomplete_detail"].as_str().unwrap();
        assert!(detail.contains("ceiling of 2 entries"), "{detail}");
        assert_eq!(out[1].metadata["l01_sub_entries_not_walked"], json!(4));

        let s = &out[2].metadata;
        assert_eq!(s["content_incomplete_reason"], json!("unvalidated"));
        assert!(out[2].data.is_some());
    }

    /// `HUNT-247`: a sparse entry naming a duplicate data offset is served
    /// what libewf reads there, the entry whose data sits at that offset is
    /// named, and the bytes are checked against the MD5 the L01 stores for the
    /// sparse entry: a match lifts the `unvalidated` stamp, a mismatch is an
    /// unresolved structure, and no stored MD5 leaves it unvalidated.
    #[test]
    fn a_sparse_entry_is_served_from_its_duplicate_offset_and_checked_against_its_stored_md5() {
        let expected: Vec<u8> = (0..12288u64).map(|i| (2 + i) as u8).collect();
        let good = seance_core::hashing::compute_hashes(&expected).md5;
        for (md5, check, reason) in [
            (Some(good.clone()), "stored_md5_matches", None),
            (
                Some("00000000000000000000000000000000".to_string()),
                "stored_md5_differs",
                Some("unresolved_structure"),
            ),
            (None, "no_stored_md5", Some("unvalidated")),
        ] {
            let mut original = entry(vec![0], Some(0), "http.db", b'f', 12288);
            original.facts.media_data_offset = Some(3_474_730);
            let mut sparse = entry(vec![1], Some(0), "https.db", b'f', 12288);
            sparse.facts.flags = Some(logical::ENTRY_FLAG_SPARSE_DATA);
            sparse.facts.media_data_size = Some(1);
            sparse.facts.media_data_offset = Some(14_766_982);
            sparse.facts.duplicate_media_data_offset = Some(3_474_730);
            sparse.facts.md5 = md5;
            let walk = logical::LogicalWalk {
                root_present: true,
                entries: vec![
                    entry(vec![], None, "LogicalEntries", b'd', 0),
                    original,
                    sparse,
                ],
                limits: Some(logical::WalkLimits::default()),
                ..logical::LogicalWalk::default()
            };
            let parent = make_artifact("x.L01", Some("e01"), Some("/e/x.L01"));
            let out = logical_artifacts(&parent, "x.L01", "/e/x.L01", &opened(walk));
            let m = &out[3].metadata;
            assert_eq!(m["l01_content_source"], json!("duplicate_data_offset"));
            assert_eq!(m["l01_duplicate_of_path"], json!("/LogicalEntries/http.db"));
            assert_eq!(m["l01_duplicate_content_check"], json!(check));
            match reason {
                None => assert!(m.get("content_incomplete").is_none(), "{m}"),
                Some(r) => assert_eq!(m["content_incomplete_reason"], json!(r), "{m}"),
            }
            let detail = m["l01_content_source_detail"].as_str().unwrap();
            assert!(detail.contains("3474730"), "{detail}");
        }

        // No duplicate offset: libewf repeats the one stored byte, and says so.
        let mut sparse = entry(vec![0], Some(0), "z.bin", b'f', 4096);
        sparse.facts.flags = Some(logical::ENTRY_FLAG_SPARSE_DATA);
        sparse.facts.media_data_size = Some(1);
        let walk = logical::LogicalWalk {
            root_present: true,
            entries: vec![entry(vec![], None, "LogicalEntries", b'd', 0), sparse],
            limits: Some(logical::WalkLimits::default()),
            ..logical::LogicalWalk::default()
        };
        let parent = make_artifact("x.L01", Some("e01"), Some("/e/x.L01"));
        let out = logical_artifacts(&parent, "x.L01", "/e/x.L01", &opened(walk));
        let m = &out[2].metadata;
        assert_eq!(m["l01_content_source"], json!("sparse_one_byte_repeated"));
        assert_eq!(m["content_incomplete_reason"], json!("unvalidated"));
    }

    /// `HUNT-246`: data EnCase stores against a directory entry is served as
    /// the directory's own `:l01_directory_data` stream, undecoded; a directory
    /// that records no size and stores one byte (libewf's empty-entry form) is
    /// flagged and counted, not served; the inventory counts both, and the
    /// streams are not counted as entries.
    #[test]
    fn a_directory_s_own_data_is_served_as_its_stream_and_not_decoded() {
        let mut photo_dir = entry(vec![0], Some(0), "IMG_0061.JPG", b'd', 192);
        photo_dir.facts.media_data_offset = Some(0x138);
        let mut folder = entry(vec![1], Some(0), "Media", b'd', 0);
        folder.facts.media_data_size = Some(1);
        let walk = logical::LogicalWalk {
            root_present: true,
            entries: vec![
                entry(vec![], None, "LogicalEntries", b'd', 0),
                photo_dir,
                entry(vec![0, 0], Some(1), "IMG_0061.JPG", b'f', 595_432),
                folder,
            ],
            limits: Some(logical::WalkLimits::default()),
            ..logical::LogicalWalk::default()
        };
        let parent = make_artifact("x.L01", Some("e01"), Some("/e/x.L01"));
        let out = logical_artifacts(&parent, "x.L01", "/e/x.L01", &opened(walk));
        let inv = &out[0].metadata;
        assert_eq!(inv["entries_published"], json!(4));
        assert_eq!(inv["directory_data_streams_published"], json!(1));
        assert_eq!(inv["directory_placeholder_bytes_not_served"], json!(1));
        assert!(inv.get("directories_with_data_not_served").is_none());

        let dir = &out[2];
        assert!(
            dir.data.is_none(),
            "the directory itself still has no bytes"
        );
        let stream = &out[3];
        let m = &stream.metadata;
        assert_eq!(
            m["path"],
            json!("/LogicalEntries/IMG_0061.JPG:l01_directory_data")
        );
        assert_eq!(
            m["l01_directory_data_of"],
            json!("/LogicalEntries/IMG_0061.JPG")
        );
        assert_eq!(m["l01_record_kind"], json!("directory_data"));
        assert_eq!(m["l01_directory_data_decoded"], json!(false));
        assert_eq!(m["is_directory"], json!(false));
        assert_eq!(m["l01_index_path"], json!([0]));
        let src = stream.data.as_ref().expect("the stream is served");
        assert_eq!(src.size(), 192);
        let mut buf = [0u8; 4];
        src.read_at(0, &mut buf).unwrap();
        assert_eq!(buf[0], 1, "the directory's own ordinal is read");

        let folder = &out[5].metadata;
        assert_eq!(folder["path"], json!("/LogicalEntries/Media"));
        assert_eq!(folder["l01_directory_placeholder_byte"], json!(true));
        assert!(out[5].data.is_none());
    }

    /// `HUNT-250`: the placeholder's one byte, read by the walk, is recorded
    /// as a value on the directory and never served or given a meaning; a
    /// byte that could not be read is absent, with the read error on the entry.
    #[test]
    fn a_directory_placeholder_s_one_byte_is_recorded_not_decoded() {
        let mut read = entry(vec![0], Some(0), "Parsed", b'd', 0);
        read.facts.media_data_size = Some(1);
        read.facts.media_data_offset = Some(0x200);
        read.facts.placeholder_byte = Some(0xE5);
        let mut unread = entry(vec![1], Some(0), "Media", b'd', 0);
        unread.facts.media_data_size = Some(1);
        unread.facts.media_data_offset = Some(0x201);
        unread.facts.errors = vec!["placeholder_byte: read failed".into()];
        let walk = logical::LogicalWalk {
            root_present: true,
            entries: vec![entry(vec![], None, "LogicalEntries", b'd', 0), read, unread],
            limits: Some(logical::WalkLimits::default()),
            ..logical::LogicalWalk::default()
        };
        let parent = make_artifact("x.L01", Some("e01"), Some("/e/x.L01"));
        let out = logical_artifacts(&parent, "x.L01", "/e/x.L01", &opened(walk));
        let inv = &out[0].metadata;
        assert_eq!(inv["directory_placeholder_bytes_not_served"], json!(2));
        assert_eq!(inv["directory_placeholder_values_recorded"], json!(1));

        let m = &out[2].metadata;
        assert_eq!(m["l01_directory_placeholder_byte"], json!(true));
        assert_eq!(m["l01_directory_placeholder_value"], json!(229));
        assert!(out[2].data.is_none(), "the byte is not served as content");
        let detail = m["l01_directory_data_detail"].as_str().unwrap();
        assert!(detail.contains("not established"), "{detail}");
        assert!(detail.contains("not content"), "{detail}");

        let m = &out[3].metadata;
        assert!(m.get("l01_directory_placeholder_value").is_none());
        assert_eq!(
            m["l01_field_errors"],
            json!(["placeholder_byte: read failed"])
        );
        let detail = m["l01_directory_data_detail"].as_str().unwrap();
        assert!(detail.contains("could not be read"), "{detail}");
    }

    /// `HUNT-250`: "stored for this entry alone" is said only when the walk
    /// checked it: no other walked entry's stored span covers the placeholder's
    /// byte. A byte inside another entry's span is said to be shared; on an
    /// incomplete walk the check is not made; a placeholder with no usable
    /// media offset is said not to have been read, not to have failed.
    #[test]
    fn a_placeholder_byte_is_called_its_own_only_when_no_other_stored_span_covers_it() {
        let placeholder = |ix: u32, name: &str, off: Option<i64>, byte: Option<u8>| {
            let mut e = entry(vec![ix], Some(0), name, b'd', 0);
            e.facts.media_data_size = Some(1);
            e.facts.media_data_offset = off;
            e.facts.placeholder_byte = byte;
            e
        };
        let mut before = entry(vec![0], Some(0), "a.bin", b'f', 0x200);
        before.facts.media_data_offset = Some(0);
        let mut around = entry(vec![2], Some(0), "b.bin", b'f', 0xFF);
        around.facts.media_data_offset = Some(0x201);
        let walk = logical::LogicalWalk {
            root_present: true,
            entries: vec![
                entry(vec![], None, "LogicalEntries", b'd', 0),
                before,
                placeholder(1, "Alone", Some(0x200), Some(0xE5)),
                around,
                placeholder(3, "Inside", Some(0x210), Some(0x00)),
            ],
            limits: Some(logical::WalkLimits::default()),
            ..logical::LogicalWalk::default()
        };
        let parent = make_artifact("x.L01", Some("e01"), Some("/e/x.L01"));
        let out = logical_artifacts(&parent, "x.L01", "/e/x.L01", &opened(walk.clone()));
        let by_name = |out: &[Artifact], n: &str| {
            out.iter()
                .find(|a| a.metadata["name"] == json!(n))
                .unwrap()
                .metadata
                .clone()
        };
        let inv = &out[0].metadata;
        assert_eq!(inv["directory_placeholder_bytes_not_served"], json!(2));
        assert_eq!(inv["directory_placeholder_values_recorded"], json!(2));
        assert_eq!(inv["directory_placeholder_bytes_alone"], json!(1));
        assert_eq!(inv["directory_placeholder_bytes_in_shared_span"], json!(1));
        assert_eq!(inv["directory_placeholder_spans_checked"], json!(true));
        assert_eq!(inv["stored_spans_unknown"], json!(0));

        let m = by_name(&out, "Alone");
        assert_eq!(m["l01_directory_placeholder_byte_span"], json!("alone"));
        let d = m["l01_directory_data_detail"].as_str().unwrap();
        assert!(d.contains("no other entry"), "{d}");

        let m = by_name(&out, "Inside");
        assert_eq!(m["l01_directory_placeholder_value"], json!(0));
        assert_eq!(m["l01_directory_placeholder_byte_span"], json!("shared"));
        let d = m["l01_directory_data_detail"].as_str().unwrap();
        assert!(!d.contains("alone"), "{d}");
        assert!(d.contains("another entry"), "{d}");

        // An incomplete walk compares only what it walked: no claim is made.
        let mut partial = walk;
        partial.entry_cap_reached = true;
        let out = logical_artifacts(&parent, "x.L01", "/e/x.L01", &opened(partial));
        let inv = &out[0].metadata;
        assert_eq!(inv["directory_placeholder_bytes_alone"], json!(0));
        assert_eq!(inv["directory_placeholder_bytes_in_shared_span"], json!(0));
        let m = by_name(&out, "Alone");
        assert_eq!(
            m["l01_directory_placeholder_byte_span"],
            json!("not_checked_walk_incomplete")
        );
        let d = m["l01_directory_data_detail"].as_str().unwrap();
        assert!(!d.contains("alone"), "{d}");
        assert!(d.contains("not checked"), "{d}");
    }

    /// `HUNT-250`: "could not look" is not "none". When libewf would not give
    /// where some entry's data is stored (a field error on its media offset or
    /// size, or a stored byte at no usable offset), that data could cover any
    /// placeholder's byte, so no placeholder is called alone.
    #[test]
    fn a_placeholder_is_not_called_alone_when_another_entry_s_span_is_unknown() {
        let placeholder = |ix: u32, name: &str, off: Option<i64>, byte: Option<u8>| {
            let mut e = entry(vec![ix], Some(0), name, b'd', 0);
            e.facts.media_data_size = Some(1);
            e.facts.media_data_offset = off;
            e.facts.placeholder_byte = byte;
            e
        };
        let mut before = entry(vec![0], Some(0), "a.bin", b'f', 0x200);
        before.facts.media_data_offset = Some(0);
        let mut lost = entry(vec![2], Some(0), "lost.bin", b'f', 0x10);
        lost.facts.media_data_offset = None;
        lost.facts
            .errors
            .push("media_data_offset: libewf said no".into());
        let parent = make_artifact("x.L01", Some("e01"), Some("/e/x.L01"));
        let by_name = |out: &[Artifact], n: &str| {
            out.iter()
                .find(|a| a.metadata["name"] == json!(n))
                .unwrap()
                .metadata
                .clone()
        };
        let check = |walk: logical::LogicalWalk, unknown: usize| {
            let out = logical_artifacts(&parent, "x.L01", "/e/x.L01", &opened(walk));
            let inv = &out[0].metadata;
            assert_eq!(inv["directory_placeholder_bytes_alone"], json!(0));
            assert_eq!(inv["directory_placeholder_bytes_in_shared_span"], json!(0));
            assert_eq!(inv["directory_placeholder_spans_checked"], json!(false));
            assert_eq!(inv["stored_spans_unknown"], json!(unknown));
            let m = by_name(&out, "Placeholder");
            assert_eq!(m["l01_directory_placeholder_value"], json!(0xE5));
            assert_eq!(
                m["l01_directory_placeholder_byte_span"],
                json!("not_checked_span_unknown")
            );
            let d = m["l01_directory_data_detail"].as_str().unwrap();
            assert!(d.contains("not checked"), "{d}");
            assert!(!d.contains("no other entry"), "{d}");
            out
        };
        let root = entry(vec![], None, "LogicalEntries", b'd', 0);
        let walk = |extra: logical::LogicalEntry| logical::LogicalWalk {
            root_present: true,
            entries: vec![
                root.clone(),
                before.clone(),
                placeholder(1, "Placeholder", Some(0x200), Some(0xE5)),
                extra,
            ],
            limits: Some(logical::WalkLimits::default()),
            ..logical::LogicalWalk::default()
        };

        // A file entry whose media offset libewf would not give.
        check(walk(lost), 1);

        // A placeholder with no usable offset is itself an unknown span, and
        // its own byte is said not to have been read, not to have failed.
        let out = check(walk(placeholder(3, "NoOffset", None, None)), 1);
        let m = by_name(&out, "NoOffset");
        assert!(m.get("l01_directory_placeholder_value").is_none());
        assert_eq!(
            m["l01_directory_placeholder_byte_span"],
            json!("no_usable_offset")
        );
        let d = m["l01_directory_data_detail"].as_str().unwrap();
        assert!(d.contains("not read: no usable media offset"), "{d}");
        assert!(!d.contains("l01_field_errors"), "{d}");
    }

    /// Names are not unique and may carry the path separator; the index path
    /// stays the identity and the ambiguity is flagged.
    #[test]
    fn a_name_carrying_a_slash_is_flagged_and_an_unreadable_name_is_not_invented() {
        let mut nameless = entry(vec![1], Some(0), "", b'f', 0);
        nameless.facts.name = None;
        let walk = logical::LogicalWalk {
            root_present: true,
            entries: vec![
                entry(vec![], None, "LogicalEntries", b'd', 0),
                entry(vec![0], Some(0), "a/b", b'f', 0),
                nameless,
            ],
            limits: Some(logical::WalkLimits::default()),
            ..logical::LogicalWalk::default()
        };
        let parent = make_artifact("x.L01", Some("e01"), Some("/e/x.L01"));
        let out = logical_artifacts(&parent, "x.L01", "/e/x.L01", &opened(walk));
        assert_eq!(out[2].metadata["name_contains_path_separator"], json!(true));
        assert_eq!(out[3].metadata["name_unreadable"], json!(true));
        assert_eq!(out[0].metadata["unreadable_names"], json!(1));
    }
}
