#![no_main]

use libfuzzer_sys::fuzz_target;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::ByteSliceDataSource,
    module::ForensicsModule,
};
use std::sync::Arc;
use uuid::Uuid;

/// Let the plugin's own `catch_unwind` do its job.
///
/// `libfuzzer-sys` installs a panic hook that ABORTS the process on any panic,
/// so a panic the plugin deliberately isolates — the upstream `evtx` decoder's
/// length-prefix overflow on a corrupt chunk, which `EvtxParser::process`
/// catches per chunk, counts and discloses — was reported as a crash of the
/// parser, and the two stored reproducers for it kept "crashing" after the
/// plugin had been fixed. The standard hook only prints; a panic that ESCAPES
/// the plugin still unwinds into libFuzzer's `extern "C"` frame and aborts, so
/// what this target now reports is what the product would actually do.
static PANIC_HOOK: std::sync::Once = std::sync::Once::new();

fuzz_target!(|data: &[u8]| {
    PANIC_HOOK.call_once(|| {
        std::panic::set_hook(Box::new(|_| {}));
    });
    // ElfFile header + first chunk
    if data.len() < 512 {
        return;
    }

    // Prepend "ElfFile\0" magic so detect_file_type() recognizes it as EVTX
    let mut buf = Vec::with_capacity(8 + data.len());
    buf.extend_from_slice(b"ElfFile\0");
    buf.extend_from_slice(data);

    let ds = Arc::new(ByteSliceDataSource::new(buf));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::SystemArtifact,
        Some(ds),
        serde_json::json!({"name": "fuzz_input"}),
    );

    let parser = seance_plugin_evtx::EvtxParser;
    let _ = parser.process(&artifact);
});
