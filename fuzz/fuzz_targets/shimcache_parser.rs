#![no_main]

use libfuzzer_sys::fuzz_target;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::ByteSliceDataSource,
    module::ForensicsModule,
};
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

/// Let the plugin's own `catch_unwind`, where it has one, do its job; a panic
/// that escapes the plugin still aborts. See `evtx_parser.rs`.
static PANIC_HOOK: std::sync::Once = std::sync::Once::new();

fuzz_target!(|data: &[u8]| {
    PANIC_HOOK.call_once(|| {
        std::panic::set_hook(Box::new(|_| {}));
    });
    // Prepend the signature detection gates on, so fuzzing spends its time
    // past the gate rather than on inputs the first bytes reject.
    let mut buf = Vec::with_capacity(8 + data.len());
    buf.extend_from_slice(b"regf");
    buf.extend_from_slice(data);

    let ds = Arc::new(ByteSliceDataSource::new(buf));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "SYSTEM"}),
    );

    let parser = seance_plugin_shimcache::ShimcacheParser;
    let _ = parser.process(&artifact);
});
