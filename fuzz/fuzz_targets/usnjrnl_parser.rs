#![no_main]
//! $UsnJrnl, which is attacker-influenced by construction.
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
    // The shape an NTFS walk produces, and the only shape this module accepts.
    //
    // This target used to name the artifact `$UsnJrnl` with no stream, which
    // `usn_journal_stream_label` **refuses** — `$UsnJrnl` on its own is the
    // base record, not the `$J` change stream, and the unit test
    // `the_max_stream_and_the_base_record_are_not_parsed_as_journal` pins that
    // exact metadata as must-not-decode. So every input returned
    // `Ok(vec![])`, the record-length walk this target exists to exercise was
    // never reached, and it was counted as live coverage of the USN journal. `a_fuzz_targets_artifact_shape_reaches_the_record_walk` in
    // the crate pins this metadata so it cannot go dead again in silence.
    let artifact = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::SystemArtifact,
        Some(ds),
        serde_json::json!({"name": "$UsnJrnl:$J", "stream_name": "$J"}),
    );
    let _ = seance_plugin_usnjrnl::UsnJrnlParser.process(&artifact);
});
