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
    // MBR (512) + potential GPT header at 512
    if data.len() < 1024 {
        return;
    }

    // Inject MBR boot signature at offsets 510-511
    let mut buf = data.to_vec();
    buf[510] = 0x55;
    buf[511] = 0xAA;

    let ds = Arc::new(ByteSliceDataSource::new(buf));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::RawEvidence,
        Some(ds),
        serde_json::json!({"name": "fuzz_input"}),
    );

    let parser = seance_plugin_partition::PartitionParser;
    let _ = parser.process(&artifact);
});
