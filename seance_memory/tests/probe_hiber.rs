//! Temporary probe: the record round trip through PhysicalLayer.
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::{DataSource, FileDataSource};
use seance_core::module::ForensicsModule;
use seance_memory::meta::LayerMeta;
use seance_memory::scan::{derive_sections, ScanConfig};
use seance_memory::{MemoryImageFormat, MemoryLayer, PhysicalLayer};
use std::sync::Arc;

#[test]
fn probe() {
    let Ok(path) = std::env::var("SEANCE_WIN_HIBERFIL") else {
        return;
    };
    let source: Arc<dyn DataSource> =
        Arc::new(FileDataSource::new(std::path::PathBuf::from(path)).expect("open"));
    let evidence = Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::RawEvidence,
        Some(Arc::clone(&source)),
        serde_json::json!({"name": "hiberfil.sys", "memory_image_format": "hibernation"}),
    );
    let out = seance_memory::module::MemoryImageModule
        .process(&evidence)
        .expect("decode");
    let record = out
        .iter()
        .find(|a| a.metadata["type"] == "MemoryImage")
        .expect("record");
    let ranges: Vec<(u64, u64)> = record.metadata["backed_ranges"]
        .as_array()
        .expect("ranges")
        .iter()
        .map(|r| (r["start"].as_u64().unwrap(), r["length"].as_u64().unwrap()))
        .collect();
    let decoded = record.data.as_ref().expect("a decoded source");
    eprintln!("decoded source size {}", decoded.size());
    let layer = PhysicalLayer::new(
        Arc::clone(decoded),
        LayerMeta::new(MemoryImageFormat::WindowsHibernation),
    )
    .expect("layer")
    .with_backed(ranges.clone());
    eprintln!(
        "layer min {:#x} max {:#x} size {}",
        layer.min_address(),
        layer.max_address(),
        layer.size()
    );
    for probe in [0u64, 4096, ranges[0].0, ranges[1].0] {
        match layer.mapping(probe, 4096) {
            Ok(runs) => eprintln!("mapping({probe:#x}) -> {} runs", runs.len()),
            Err(e) => eprintln!("mapping({probe:#x}) -> {e}"),
        }
    }
    match derive_sections(&layer, &ScanConfig::default()) {
        Ok(plan) => eprintln!(
            "sections {} mapped {} truncated {:?}",
            plan.sections.len(),
            plan.mapped_len(),
            plan.truncated_at
        ),
        Err(e) => eprintln!("derive_sections error: {e}"),
    }
}
