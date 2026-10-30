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
    // regf header + first hbin
    if data.len() < 512 {
        return;
    }

    // Prepend "regf" magic so detect_file_type() recognizes it as a registry hive
    let mut buf = Vec::with_capacity(4 + data.len());
    buf.extend_from_slice(b"regf");
    buf.extend_from_slice(data);

    let ds = Arc::new(ByteSliceDataSource::new(buf));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::SystemArtifact,
        Some(ds),
        serde_json::json!({"name": "fuzz_input"}),
    );

    let parser = seance_plugin_registry::RegistryParser;
    let _ = parser.process(&artifact);
});
