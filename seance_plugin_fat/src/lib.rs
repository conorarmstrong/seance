#![forbid(unsafe_code)]

use anyhow::Result;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    module::{ForensicsModule, InputCapability, ModuleError},
};
use tracing::{debug, info};

mod exfat_parser;
mod exfat_structs;
mod fat_parser;
mod fat_structs;

use fat_parser::*;

pub struct FatParser;

impl ForensicsModule for FatParser {
    fn id(&self) -> &str {
        "plugin.filesystem.fat_parser"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::FileSystem]
    }

    fn input_capability(&self) -> InputCapability {
        InputCapability::Stream
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        // Only process FAT-family filesystems
        if let Some(subtype) = artifact.subtype() {
            match subtype {
                "fat32" | "fat16" | "fat12" | "exfat" | "fat" => {}
                _ => return Ok(Vec::new()),
            }
        }

        debug!("FatParser processing artifact ID: {}", artifact.id);

        let data_source = artifact.data.as_ref().ok_or_else(|| {
            ModuleError::InvalidInputFormat("FAT parser requires a data source".to_string())
        })?;

        // Try to parse as FAT filesystem
        match parse_fat_filesystem(artifact, data_source.clone()) {
            Ok(mut artifacts) => {
                if !artifacts.is_empty() {
                    info!(
                        "Successfully parsed FAT filesystem from artifact {}",
                        artifact.id
                    );
                    // Publish in-image sidecars (`-wal`, `.LOG1`/`.LOG2`)
                    // through `open_sibling` so registry log replay and
                    // WAL-aware SQLite spills reach them inside a disk image
                    // (BUG-257).
                    seance_core::data_source::attach_sibling_bundles(&mut artifacts);
                    Ok(artifacts)
                } else {
                    // Not a FAT filesystem
                    Ok(Vec::new())
                }
            }
            Err(e) => {
                debug!("Failed to parse as FAT filesystem: {}", e);
                Ok(Vec::new())
            }
        }
    }
}

#[cfg(test)]
mod tests;
