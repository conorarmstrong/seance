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
    // The UDF anchor sits at sector 256 (or the last sector, or N-257), in
    // 2048-byte sectors; the seed corpus holds whole in-memory-built volumes
    // (`seance_plugin_udf`'s `write_fuzz_seeds` test) so mutation reaches the
    // descriptor sequence, the file set and the directory walk.
    if data.len() < 2048 {
        return;
    }

    let ds = Arc::new(ByteSliceDataSource::new(data.to_vec()));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(ds),
        serde_json::json!({"name": "fuzz", "subtype": "udf"}),
    );

    let parser = seance_plugin_udf::UdfParser;
    if let Ok(out) = parser.process(&artifact) {
        // Reading content exercises the run lists the walk built.
        for a in &out {
            if let Some(ds) = a.data.as_ref() {
                let mut buf = [0u8; 4096];
                let _ = ds.read_at(0, &mut buf);
            }
        }
    }
});
