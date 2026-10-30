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
    // MFT entry is 1024 bytes
    if data.len() < 1024 {
        return;
    }

    let ds = Arc::new(ByteSliceDataSource::new(data.to_vec()));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::SystemArtifact,
        Some(ds),
        serde_json::json!({"name": "fuzz_input"}),
    );

    let parser = seance_plugin_mft::MftParser::new();
    let _ = parser.process(&artifact);
});
