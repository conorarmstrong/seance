//! `HUNT-163`, end to end: an orphan EVTX chunk in free space is carved, and
//! the carved file reaches the EVTX module's recovery pass.
//!
//! Graded on real chunks (`SEANCE_EVTX_CORPUS`, a directory holding plaso's
//! `System2.evtx`): its first chunk, which the intact parser reads as 104
//! records, and its third chunk as the file cuts it, placed at sector offsets
//! in unrelated bytes the way a rotated log's chunks lie in unallocated space.
//! Before the `ElfChnk` signature existed nothing was carved, so none of these
//! records could reach a case.

use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::{ByteSliceDataSource, DataSource};
use seance_core::module::ForensicsModule;
use seance_plugin_carver::UnallocatedCarver;
use seance_plugin_evtx::EvtxParser;
use std::sync::Arc;
use uuid::Uuid;

const FILE_HEADER: usize = 4096;
const CHUNK: usize = 65_536;

fn corpus(name: &str) -> Option<Vec<u8>> {
    let dir = std::env::var_os("SEANCE_EVTX_CORPUS")?;
    std::fs::read(std::path::Path::new(&dir).join(name)).ok()
}

#[test]
fn an_orphan_chunk_in_unallocated_space_is_carved_and_its_records_recovered() {
    let Some(system2) = corpus("System2.evtx") else {
        return;
    };
    let whole = &system2[FILE_HEADER..FILE_HEADER + CHUNK];
    let cut = &system2[FILE_HEADER + 2 * CHUNK..];

    let mut free_space = vec![0x5Au8; 8 * 512];
    let whole_at = free_space.len() as u64;
    free_space.extend_from_slice(whole);
    free_space.extend_from_slice(&[0xC3; 3 * 512]);
    let cut_at = free_space.len() as u64;
    free_space.extend_from_slice(cut);

    let source: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(free_space));
    let unallocated = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::UnallocatedSpace,
        Some(source),
        serde_json::json!({ "name": "unallocated" }),
    );
    let carved = UnallocatedCarver::new()
        .process(&unallocated)
        .expect("carving runs");
    let chunks: Vec<&Artifact> = carved
        .iter()
        .filter(|a| {
            a.artifact_type == ArtifactType::FileEntry
                && a.metadata["carving_signature"] == "EVTX chunk (Windows event log)"
        })
        .collect();
    assert_eq!(
        chunks.len(),
        2,
        "both orphan chunks must be carved; carved {:?}",
        carved.iter().map(|a| &a.metadata).collect::<Vec<_>>()
    );

    let mut recovered_by_chunk = Vec::new();
    for chunk in &chunks {
        let out = EvtxParser.process(chunk).expect("the EVTX module runs");
        let recovered = out
            .iter()
            .filter(|a| a.metadata["type"] == "EvtxRecoveredLogEntry")
            .count();
        assert!(
            out.iter()
                .any(|a| a.metadata["type"] == "EvtxRecoveryStatus"),
            "a headerless input always carries the recovery status"
        );
        recovered_by_chunk.push(recovered);
    }
    // The whole chunk yields every record the intact parser reads from it;
    // the cut chunk yields the 90 that begin in its surviving bytes.
    assert_eq!(
        recovered_by_chunk,
        vec![104, 90],
        "at {whole_at} and {cut_at}"
    );
}
