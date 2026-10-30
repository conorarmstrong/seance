#![no_main]
//! $LogFile, which is attacker-influenced by construction.
//!
//! The journal records every change a filesystem made, so its contents follow
//! from what ran on the machine — filenames, lengths and record boundaries all
//! reachable by whoever used it. A parser walking record-length fields taken
//! from evidence is exactly where a crafted length runs a loop off the end or
//! back on itself.

use libfuzzer_sys::fuzz_target;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::ByteSliceDataSource,
    module::ForensicsModule,
};
use std::sync::Arc;
use uuid::Uuid;

fuzz_target!(|data: &[u8]| {
    let ds = Arc::new(ByteSliceDataSource::new(data.to_vec()));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::SystemArtifact,
        Some(ds),
        serde_json::json!({"name": "$LogFile"}),
    );
    let _ = seance_plugin_logfile::LogFileParser.process(&artifact);
});
