#![no_main]

// The Apple unified-log readers: the `.tracev3` chunk walk, catalog, chunkset
// decompression and firehose tracepoint parser, the oversize, statedump and
// simpledump parsers, the Header chunk reader and the printf renderer, and the timesync database.

use libfuzzer_sys::fuzz_target;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::ByteSliceDataSource,
    module::ForensicsModule,
};
use std::sync::Arc;
use uuid::Uuid;

fn run(module: &dyn ForensicsModule, bytes: Vec<u8>, name: &str) {
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(Arc::new(ByteSliceDataSource::new(bytes))),
        serde_json::json!({ "name": name }),
    );
    let _ = module.process(&artifact);
}

/// A 16-byte chunk preamble followed by `payload`, padded to 8 bytes.
fn chunk(tag: u32, payload: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(&tag.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    out.extend_from_slice(payload);
    while out.len() % 8 != 0 {
        out.push(0);
    }
}

fuzz_target!(|data: &[u8]| {
    let tracev3 = seance_plugin_macos_artifacts::UnifiedLogParser;

    // 1. The input as the chunks after a Header chunk.
    let mut file = Vec::new();
    chunk(0x1000, &[], &mut file);
    file.extend_from_slice(data);
    run(&tracev3, file, "fuzz.tracev3");

    // 2. The input as the decompressed content of one chunkset (an
    //    uncompressed `bv4-` block), which reaches the entry walk and the
    //    firehose parser directly.
    let mut block = b"bv4-".to_vec();
    block.extend_from_slice(&(data.len() as u32).to_le_bytes());
    block.extend_from_slice(data);
    block.extend_from_slice(b"bv4$");
    let mut file = Vec::new();
    chunk(0x1000, &[], &mut file);
    chunk(0x600d, &block, &mut file);
    run(&tracev3, file, "fuzz.tracev3");

    // 3. The input as a catalog chunk.
    let mut file = Vec::new();
    chunk(0x1000, &[], &mut file);
    chunk(0x600b, data, &mut file);
    run(&tracev3, file, "fuzz.tracev3");

    // 4. The input as an oversize, statedump or simpledump entry, a Header
    //    chunk payload and a format
    //    string, which only a source that reaches its tree would otherwise
    //    see.
    seance_plugin_macos_artifacts::fuzz_unifiedlog_parts(data);

    // 5. The input as a timesync database.
    run(
        &seance_plugin_macos_artifacts::UnifiedLogTimesyncParser,
        data.to_vec(),
        "fuzz.timesync",
    );
});
