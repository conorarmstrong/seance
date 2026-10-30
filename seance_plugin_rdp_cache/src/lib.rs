#![forbid(unsafe_code)]
//! The Remote Desktop client's persistent bitmap cache.
//!
//! `mstsc` keeps the screen fragments it has received in
//! `%LOCALAPPDATA%\Microsoft\Terminal Server Client\Cache\`, so a machine that
//! was used to RDP *out* carries pieces of what the remote screens showed.
//!
//! - `Cache####.bin` (the `RDP8bmp` container): a 12-byte header (magic and a
//!   u32 version), then tiles, each an 8-byte key, a u16 width, a u16 height
//!   and `width x height` 32-bit pixels in BGRA order. Read by [`cache_bin`].
//! - `bcache*.bmc` (the older format): recognised by name. An empty one is
//!   reported as empty; a non-empty one is **not decoded** — no real sample of
//!   it has been examined — and says so.
//!
//! Each tile is emitted as a PNG `FileEntry` child, so it reaches the gallery,
//! the hasher and OCR like any picture. Every tile is also laid out, in cache
//! order, 64 across, in **one collage per file** (owner decision 2026-09-26,
//! option a). **The collage is not a reconstruction**: tiles are placed in the
//! order the cache stores them, not where they sat on the screen; its name and
//! its record say so. Nothing here fits tile edges together.

pub mod cache_bin;
pub mod collage;

use cache_bin::{Refusal, Tile};
use collage::Collage;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::{ByteSliceDataSource, DataSource},
    io::read_exact_or_fail,
    module::{ForensicsModule, InputCapability, ModuleError},
};
use serde_json::{json, Value};
use std::sync::Arc;
use uuid::Uuid;

/// Tiles walked per file; a larger count is reported as a cut.
pub const MAX_TILES: usize = 65_536;
/// Cells across the collage.
pub const COLLAGE_COLUMNS: usize = collage::COLUMNS;

/// The sentence the collage carries.
pub const COLLAGE_NOTE: &str = "not a reconstruction: every tile is laid out in the order the \
    cache file stores it, 64 across, not where it appeared on the remote screen; nothing here \
    fits tile edges together";

pub struct RdpCacheParser;

impl RdpCacheParser {
    pub fn new() -> Self {
        Self
    }

    fn file_name(artifact: &Artifact) -> String {
        artifact
            .metadata
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string()
    }

    /// `Cache0000.bin` .. `Cache9999.bin`, any case.
    pub fn named_like_cache_bin(name: &str) -> bool {
        let l = name.to_ascii_lowercase();
        l.len() == 13
            && l.starts_with("cache")
            && l.ends_with(".bin")
            && l[5..9].bytes().all(|b| b.is_ascii_digit())
    }

    /// `bcache*.bmc`, any case.
    pub fn named_like_bmc(name: &str) -> bool {
        let l = name.to_ascii_lowercase();
        l.starts_with("bcache") && l.ends_with(".bmc")
    }

    fn record(case_id: Uuid, parent_id: Uuid, subtype: &str, metadata: Value) -> Artifact {
        Artifact::new(case_id, ArtifactType::ParsedRecord, None, metadata)
            .with_parent(parent_id)
            .with_subtype(subtype)
    }

    fn not_decoded(case_id: Uuid, parent_id: Uuid, source: &str, detail: &str) -> Artifact {
        Self::record(
            case_id,
            parent_id,
            "parse_incomplete",
            json!({
                "type": "RdpBitmapCacheIncomplete",
                "status": "NotDecoded",
                "source_file": source,
                "content_incomplete": true,
                "content_incomplete_reason": detail,
                "content_incomplete_detail": detail,
                "name": format!("RDP bitmap cache {source}: {detail}"),
            }),
        )
    }

    /// Every record and tile one cache file yields. `read` fills a buffer from
    /// the file at an offset.
    pub fn records_for(
        case_id: Uuid,
        parent_id: Uuid,
        source: &str,
        size: u64,
        read: &mut dyn FnMut(u64, &mut [u8]) -> usize,
    ) -> Vec<Artifact> {
        let walked = match cache_bin::walk(size, read, MAX_TILES) {
            Ok(w) => w,
            Err(Refusal::BadMagic) => {
                return vec![Self::not_decoded(
                    case_id,
                    parent_id,
                    source,
                    "not decoded: the file does not open with the RDP8bmp magic, so no tile in it \
                     was read",
                )]
            }
            Err(Refusal::TooShort) => {
                return vec![Self::not_decoded(
                    case_id,
                    parent_id,
                    source,
                    "not decoded: the file is shorter than the 12-byte cache header",
                )]
            }
        };
        let stem = source.trim_end_matches(".bin").trim_end_matches(".BIN");
        let mut out = Vec::new();
        // The one collage is written band by band as tiles are walked, so at
        // most one band of cells' pixels is held, never the whole file's.
        let mut collage = Collage::new(walked.tiles.len());
        let mut collage_failed = false;
        let mut unreadable = 0usize;
        for tile in &walked.tiles {
            let mut px = vec![0u8; tile.width as usize * tile.height as usize * 4];
            let png = if read(tile.pixels_offset, &mut px) == px.len() {
                cache_bin::tile_png(&px, tile.width, tile.height)
            } else {
                None
            };
            let cell = match png {
                Some(png) => {
                    out.push(Self::tile_entry(
                        case_id, parent_id, source, stem, tile, png,
                    ));
                    Some((tile.width, tile.height, px.as_slice()))
                }
                None => {
                    unreadable += 1;
                    None
                }
            };
            if let Some(c) = collage.as_mut() {
                if c.push(cell).is_none() {
                    collage = None;
                    collage_failed = true;
                }
            }
        }
        let collages = match collage.map(|c| (c.columns(), c.finish())) {
            Some((cols, Some((png, placed, blank)))) => {
                out.push(Self::collage_entry(
                    case_id, parent_id, source, stem, cols, placed, blank, png,
                ));
                1
            }
            Some((_, None)) => {
                collage_failed = true;
                0
            }
            None => 0,
        };

        let mut problems: Vec<String> = walked.incomplete.iter().cloned().collect();
        if unreadable > 0 {
            problems.push(format!(
                "{unreadable} tile(s) could not be read back and are absent; their collage \
                 cells are left black"
            ));
        }
        if collage_failed {
            problems.push("the collage could not be encoded and is absent".to_string());
        }
        let emitted = walked.tiles.len() - unreadable;
        let status = format!("{emitted} tile(s), {collages} collage(s)");
        let mut m = json!({
            "type": "RdpBitmapCache",
            "source_file": source,
            "source_format": "rdp8bmp",
            "version": walked.version,
            "tiles": emitted,
            "collages": collages,
            "collage_note": COLLAGE_NOTE,
            "status": status,
            "name": format!("RDP bitmap cache {source}: {status}"),
        });
        if !problems.is_empty() {
            let why = problems.join("; ");
            m["content_incomplete"] = json!(true);
            m["content_incomplete_reason"] = json!(why);
            m["content_incomplete_detail"] = json!(why);
        }
        out.push(Self::record(case_id, parent_id, "rdp_bitmap_cache", m));
        out
    }

    fn tile_entry(
        case_id: Uuid,
        parent_id: Uuid,
        source: &str,
        stem: &str,
        tile: &Tile,
        png: Vec<u8>,
    ) -> Artifact {
        let key: String = tile.key.iter().map(|b| format!("{b:02x}")).collect();
        let size = png.len();
        Artifact::new(
            case_id,
            ArtifactType::FileEntry,
            Some(Arc::new(ByteSliceDataSource::new(png))),
            json!({
                "type": "RdpCacheTile",
                "name": format!("{stem}_tile_{:05}.png", tile.index),
                "size": size,
                "source_file": source,
                "recovery_method": "rdp_bitmap_cache",
                "tile_index": tile.index,
                "key": key,
                "width": tile.width,
                "height": tile.height,
                "source_offset": tile.offset,
                "derived_note": "a PNG re-encoding of one cache tile's pixels (blue-green-red, \
                    the fourth byte dropped); the bytes are Séance's, the pixels the cache's",
            }),
        )
        .with_parent(parent_id)
    }

    /// The file's one collage: every tile in cache order, [`COLLAGE_COLUMNS`]
    /// across, labelled as not a reconstruction.
    #[allow(clippy::too_many_arguments)]
    fn collage_entry(
        case_id: Uuid,
        parent_id: Uuid,
        source: &str,
        stem: &str,
        columns: usize,
        placed: usize,
        blank: usize,
        png: Vec<u8>,
    ) -> Artifact {
        let size = png.len();
        let cells = placed + blank;
        Artifact::new(
            case_id,
            ArtifactType::FileEntry,
            Some(Arc::new(ByteSliceDataSource::new(png))),
            json!({
                "type": "RdpCacheCollage",
                "name": format!("{stem}_collage_cache_order_not_a_reconstruction.png"),
                "size": size,
                "source_file": source,
                "recovery_method": "rdp_bitmap_cache",
                "reconstruction": false,
                "first_tile": 0,
                "last_tile": cells.saturating_sub(1),
                "tiles_placed": placed,
                "cells_blank": blank,
                "columns": columns,
                "collage_note": COLLAGE_NOTE,
            }),
        )
        .with_parent(parent_id)
    }
}

impl Default for RdpCacheParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ForensicsModule for RdpCacheParser {
    fn id(&self) -> &str {
        "plugin.windows.rdp_bitmap_cache"
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
        let Some(ds) = artifact.data.as_ref() else {
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
        let name = Self::file_name(artifact);
        let size = ds.size();
        if Self::named_like_bmc(&name) {
            return Ok(Self::bmc_records(
                artifact.case_id,
                artifact.id,
                &name,
                size,
            ));
        }
        let mut head = [0u8; 8];
        let has_magic = size >= 8
            && read_exact_or_fail(ds.as_ref(), 0, &mut head, "RDP cache magic").is_ok()
            && &head == cache_bin::MAGIC;
        if !has_magic && !Self::named_like_cache_bin(&name) {
            return Ok(Vec::new());
        }
        let source = if name.is_empty() {
            "Cache.bin".to_string()
        } else {
            name
        };
        let ds: &dyn DataSource = ds.as_ref();
        let mut read = |off: u64, buf: &mut [u8]| -> usize {
            let mut got = 0;
            while got < buf.len() {
                match ds.read_at(off + got as u64, &mut buf[got..]) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => got += n,
                }
            }
            got
        };
        Ok(Self::records_for(
            artifact.case_id,
            artifact.id,
            &source,
            size,
            &mut read,
        ))
    }
}

impl RdpCacheParser {
    fn bmc_records(case_id: Uuid, parent_id: Uuid, source: &str, size: u64) -> Vec<Artifact> {
        if size == 0 {
            let status = "empty file (0 bytes)";
            return vec![Self::record(
                case_id,
                parent_id,
                "rdp_bitmap_cache",
                json!({
                    "type": "RdpBitmapCache",
                    "source_file": source,
                    "source_format": "bmc",
                    "tiles": 0,
                    "collages": 0,
                    "status": status,
                    "name": format!("RDP bitmap cache {source}: {status}"),
                }),
            )];
        }
        vec![Self::not_decoded(
            case_id,
            parent_id,
            source,
            &format!(
                "not decoded: {size} bytes in the legacy .bmc format, which this build does not \
                 read — no real non-empty .bmc has been examined — so no tile in it was read"
            ),
        )]
    }
}

#[cfg(test)]
mod tests;
