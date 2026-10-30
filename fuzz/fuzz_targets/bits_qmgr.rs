#![no_main]

//! The BITS binary queue reader, entered both by content (the header GUIDs
//! are prepended on half the inputs so the walk is reached) and by name.

use libfuzzer_sys::fuzz_target;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::ByteSliceDataSource,
    module::ForensicsModule,
};
use std::sync::Arc;
use uuid::Uuid;

/// File GUID (Windows 7), header GUID, queue GUID.
const PREFIX: [u8; 48] = [
    0xf5, 0x6a, 0x19, 0x2b, 0x7c, 0x00, 0x8f, 0x43, 0x8d, 0x12, 0x1c, 0xfc, 0xa4, 0xcc, 0x9b, 0x76,
    0x13, 0xf7, 0x2b, 0xc8, 0x40, 0x99, 0x12, 0x4a, 0x9f, 0x1a, 0x3a, 0xae, 0xbd, 0x89, 0x4e, 0xea,
    0x47, 0x44, 0x5f, 0x00, 0xa9, 0xbd, 0xba, 0x44, 0x98, 0x51, 0xc4, 0x7b, 0xb6, 0xc0, 0x7a, 0xce,
];

fuzz_target!(|data: &[u8]| {
    let Some((&first, rest)) = data.split_first() else {
        return;
    };
    let bytes = if first & 1 == 0 {
        let mut v = PREFIX.to_vec();
        v.extend_from_slice(rest);
        v
    } else {
        rest.to_vec()
    };
    let _ = seance_plugin_bits::qmgr_dat::parse(&bytes);
    let ds = Arc::new(ByteSliceDataSource::new(bytes));
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        serde_json::json!({"name": "qmgr0.dat"}),
    );
    let _ = seance_plugin_bits::BitsParser.process(&artifact);
});
