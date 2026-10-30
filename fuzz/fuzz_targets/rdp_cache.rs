#![no_main]

//! The RDP bitmap cache walker. The magic is prepended so the tile walk is
//! reached; tile sides are bounded at 64, so a tile costs at most 16 KiB.

use libfuzzer_sys::fuzz_target;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::ByteSliceDataSource,
    module::ForensicsModule,
};
use std::sync::Arc;
use uuid::Uuid;

fuzz_target!(|data: &[u8]| {
    let mut bytes = seance_plugin_rdp_cache::cache_bin::MAGIC.to_vec();
    bytes.extend_from_slice(data);
    let ds = Arc::new(ByteSliceDataSource::new(bytes));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        serde_json::json!({"name": "Cache0000.bin"}),
    );
    let _ = seance_plugin_rdp_cache::RdpCacheParser.process(&artifact);
});
