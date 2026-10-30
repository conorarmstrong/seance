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
    // ext4 superblock at offset 1024
    if data.len() < 2048 {
        return;
    }

    let ds = Arc::new(ByteSliceDataSource::new(data.to_vec()));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(ds),
        serde_json::json!({"name": "fuzz", "subtype": "ext4"}),
    );

    let parser = seance_plugin_ext4::Ext4Parser::new();
    let _ = parser.process(&artifact);
});
