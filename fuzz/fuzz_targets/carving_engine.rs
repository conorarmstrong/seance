#![no_main]

use libfuzzer_sys::fuzz_target;
use seance_carving::engine::CarvingDataSource;
use seance_carving::formats::register_all;
use seance_carving::{CarvingEngine, SignatureRegistry};
use std::io;
use std::sync::Arc;

/// In-memory data source for fuzzing.
struct FuzzDataSource {
    data: Vec<u8>,
}

impl CarvingDataSource for FuzzDataSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        let off = offset as usize;
        if off >= self.data.len() {
            return Ok(0);
        }
        let available = self.data.len() - off;
        let to_read = buf.len().min(available);
        buf[..to_read].copy_from_slice(&self.data[off..off + to_read]);
        Ok(to_read)
    }

    fn size(&self) -> u64 {
        self.data.len() as u64
    }
}

fuzz_target!(|data: &[u8]| {
    // Accept inputs from 1 byte up to 256 KB to cover both tiny
    // and moderately sized malformed inputs.
    if data.is_empty() || data.len() > 256 * 1024 {
        return;
    }

    let mut registry = SignatureRegistry::new();
    register_all(&mut registry);

    let engine = CarvingEngine::new(Arc::new(registry));
    let source = FuzzDataSource {
        data: data.to_vec(),
    };

    // Run the scan — should never panic regardless of input.
    let _results = engine.scan(&source, source.size());
});
