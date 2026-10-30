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
    // APFS container superblock at block 0
    if data.len() < 4096 {
        return;
    }

    let ds = Arc::new(ByteSliceDataSource::new(data.to_vec()));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(ds),
        serde_json::json!({"name": "fuzz", "subtype": "apfs"}),
    );

    let parser = seance_plugin_apfs::ApfsParser;
    let _ = parser.process(&artifact);
});
