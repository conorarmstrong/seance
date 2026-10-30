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
    // Shell link header (76 bytes) + some data
    if data.len() < 128 {
        return;
    }

    let ds = Arc::new(ByteSliceDataSource::new(data.to_vec()));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        serde_json::json!({"name": "fuzz.lnk"}),
    );

    let parser = seance_plugin_lnk::LnkParser;
    let _ = parser.process(&artifact);
});
