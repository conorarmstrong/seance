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
    let buf = data.to_vec();

    let ds = Arc::new(ByteSliceDataSource::new(buf));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "1b4dd67f29cb1962.automaticDestinations-ms"}),
    );

    let parser = seance_plugin_jumplists::JumpListParser;
    let _ = parser.process(&artifact);
});
