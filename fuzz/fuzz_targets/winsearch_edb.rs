#![no_main]

//! The Windows Search index reader: the obfuscated-text decoder on the raw
//! bytes, and the whole module entered by name with the ESE signature
//! prepended so the database open, and not only the name gate, is reached.

use libfuzzer_sys::fuzz_target;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::ByteSliceDataSource,
    module::ForensicsModule,
};
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

static PANIC_HOOK: std::sync::Once = std::sync::Once::new();

fuzz_target!(|data: &[u8]| {
    PANIC_HOOK.call_once(|| {
        std::panic::set_hook(Box::new(|_| {}));
    });
    let _ = seance_plugin_winsearch_edb::compression::deobfuscate(data);
    let _ = seance_plugin_winsearch_edb::compression::decode_text(data);

    // ESE header: checksum (4), then the 0x89ABCDEF signature at offset 4.
    let mut buf = Vec::with_capacity(8 + data.len());
    buf.extend_from_slice(b"\x00\x00\x00\x00\xef\xcd\xab\x89");
    buf.extend_from_slice(data);
    let ds = Arc::new(ByteSliceDataSource::new(buf));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({"name": "Windows.edb"}),
    );
    let _ = seance_plugin_winsearch_edb::WinSearchParser::new().process(&artifact);
});
