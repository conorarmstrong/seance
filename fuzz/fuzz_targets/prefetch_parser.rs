#![no_main]

use libfuzzer_sys::fuzz_target;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::ByteSliceDataSource,
    module::ForensicsModule,
};
use std::sync::Arc;
use uuid::Uuid;

fuzz_target!(|data: &[u8]| {
    // SCCA header + basic data
    if data.len() < 256 {
        return;
    }

    // Prepend prefetch header: version 17 (Win XP) + "SCCA" signature
    let mut buf = Vec::with_capacity(8 + data.len());
    buf.extend_from_slice(&17u32.to_le_bytes()); // version at offset 0
    buf.extend_from_slice(b"SCCA");              // signature at offset 4
    buf.extend_from_slice(data);

    let ds = Arc::new(ByteSliceDataSource::new(buf));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::SystemArtifact,
        Some(ds),
        serde_json::json!({"name": "fuzz_input"}),
    );

    let parser = seance_plugin_prefetch::PrefetchParser;
    let _ = parser.process(&artifact);
});
