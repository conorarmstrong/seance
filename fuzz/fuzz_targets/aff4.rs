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
    if data.is_empty() {
        return;
    }

    let ds = Arc::new(ByteSliceDataSource::new(data.to_vec()));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::Container,
        Some(ds),
        serde_json::json!({"name": "fuzz.aff4", "subtype": "aff4"}),
    );

    let module = seance_container_aff4::Aff4ContainerModule;
    let _ = module.process(&artifact);
});
