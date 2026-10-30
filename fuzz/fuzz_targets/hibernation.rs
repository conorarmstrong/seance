#![no_main]

use libfuzzer_sys::fuzz_target;
use seance_core::data_source::{ByteSliceDataSource, DataSource};
use std::sync::Arc;

fuzz_target!(|data: &[u8]| {
    let _ = seance_memory::formats::hibernation::identify(data);
    let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data.to_vec()));
    let _ = seance_memory::formats::hibernation::open(src);
});
