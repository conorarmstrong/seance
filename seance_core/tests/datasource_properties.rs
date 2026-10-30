use proptest::prelude::*;
use seance_core::data_source::{DataSource, FileDataSource, RunListDataSource, WindowSource};
use std::io::Write;
use std::sync::Arc;
use tempfile::NamedTempFile;

// Property: read_at always returns <= buf.len()
proptest! {
    #[test]
    fn prop_read_at_respects_buffer_size(offset in 0u64..1000, buf_size in 1usize..1000) {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(&vec![0xAB; 2000]).unwrap();
        temp_file.flush().unwrap();

        let source = FileDataSource::new(temp_file.path().to_path_buf()).unwrap();
        let mut buffer = vec![0u8; buf_size];

        let bytes_read = source.read_at(offset, &mut buffer).unwrap();

        prop_assert!(bytes_read <= buf_size,
            "read_at returned {} bytes but buffer size is {}", bytes_read, buf_size);
    }
}

// Property: read_at with offset >= size() returns 0
proptest! {
    #[test]
    fn prop_read_at_beyond_size_returns_zero(offset_delta in 0u64..1000, buf_size in 1usize..100) {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(&vec![0xCD; 1000]).unwrap();
        temp_file.flush().unwrap();

        let source = FileDataSource::new(temp_file.path().to_path_buf()).unwrap();
        let size = source.size();
        let offset = size + offset_delta;
        let mut buffer = vec![0u8; buf_size];

        let bytes_read = source.read_at(offset, &mut buffer).unwrap();

        prop_assert_eq!(bytes_read, 0,
            "read_at at offset {} (size={}) should return 0 bytes", offset, size);
    }
}

// Property: Sequential small reads equivalent to single large read
proptest! {
    #[test]
    fn prop_sequential_reads_equivalent(
        chunk_size in 1usize..100,
        num_chunks in 1usize..10
    ) {
        let total_size = chunk_size * num_chunks;
        let test_data: Vec<u8> = (0..total_size).map(|i| (i % 256) as u8).collect();

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(&test_data).unwrap();
        temp_file.flush().unwrap();

        let source = FileDataSource::new(temp_file.path().to_path_buf()).unwrap();

        // Sequential small reads
        let mut sequential_data = Vec::new();
        for i in 0..num_chunks {
            let mut chunk = vec![0u8; chunk_size];
            let bytes_read = source.read_at((i * chunk_size) as u64, &mut chunk).unwrap();
            sequential_data.extend_from_slice(&chunk[..bytes_read]);
        }

        // Single large read
        let mut large_buffer = vec![0u8; total_size];
        let large_bytes_read = source.read_at(0, &mut large_buffer).unwrap();

        prop_assert_eq!(&sequential_data[..], &large_buffer[..large_bytes_read],
            "Sequential reads should produce same data as single large read");
    }
}

// WindowSource Property: Reads beyond window size return 0
proptest! {
    #[test]
    fn prop_window_source_respects_bounds(
        window_start in 0u64..500,
        window_length in 100u64..500,
        offset_delta in 0u64..100
    ) {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(&vec![0xEF; 2000]).unwrap();
        temp_file.flush().unwrap();

        let inner_source = Arc::new(FileDataSource::new(temp_file.path().to_path_buf()).unwrap());
        let window = WindowSource {
            inner: inner_source,
            start_offset: window_start,
            length: window_length,
        };

        // Read at offset beyond window length
        let offset = window_length + offset_delta;
        let mut buffer = vec![0u8; 100];

        let bytes_read = window.read_at(offset, &mut buffer).unwrap();

        prop_assert_eq!(bytes_read, 0,
            "WindowSource read at offset {} (length={}) should return 0 bytes", offset, window_length);
    }
}

// WindowSource Property: Offset translation is consistent
proptest! {
    #[test]
    fn prop_window_source_offset_translation(
        window_start in 0u64..500,
        window_length in 100u64..500,
        read_offset in 0u64..50
    ) {
        let test_data: Vec<u8> = (0..2000).map(|i| (i % 256) as u8).collect();

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(&test_data).unwrap();
        temp_file.flush().unwrap();

        let inner_source = Arc::new(FileDataSource::new(temp_file.path().to_path_buf()).unwrap());

        // Read from window at offset
        let window = WindowSource {
            inner: inner_source.clone(),
            start_offset: window_start,
            length: window_length,
        };

        let mut window_buffer = vec![0u8; 50];
        let window_bytes = window.read_at(read_offset, &mut window_buffer).unwrap();

        // Read from inner source at translated offset
        let mut inner_buffer = vec![0u8; 50];
        let inner_bytes = inner_source.read_at(window_start + read_offset, &mut inner_buffer).unwrap();

        prop_assert_eq!(window_bytes, inner_bytes,
            "WindowSource should read same number of bytes as inner source");
        prop_assert_eq!(&window_buffer[..window_bytes], &inner_buffer[..inner_bytes],
            "WindowSource should return same data as inner source at translated offset");
    }
}

// RunListDataSource Property: Logical offset mapping is deterministic
proptest! {
    #[test]
    fn prop_runlist_deterministic(
        fragments in prop::collection::vec((0u64..100, 10u64..50), 1..5),
        read_offset in 0u64..100
    ) {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(&vec![0x42; 1000]).unwrap();
        temp_file.flush().unwrap();

        let inner_source = Arc::new(FileDataSource::new(temp_file.path().to_path_buf()).unwrap());

        let runs: Vec<(Option<u64>, u64)> = fragments.into_iter().map(|(offset, len)| (Some(offset), len)).collect();

        let runlist = RunListDataSource::from_allocation(inner_source, runs);

        // Read same offset twice
        let mut buffer1 = vec![0u8; 20];
        let mut buffer2 = vec![0u8; 20];

        let bytes1 = runlist.read_at(read_offset, &mut buffer1).unwrap();
        let bytes2 = runlist.read_at(read_offset, &mut buffer2).unwrap();

        prop_assert_eq!(bytes1, bytes2,
            "RunListDataSource should read same number of bytes for same offset");
        prop_assert_eq!(&buffer1[..bytes1], &buffer2[..bytes2],
            "RunListDataSource should return same data for same offset (deterministic)");
    }
}

// RunListDataSource Property: Read beyond total_size returns 0
proptest! {
    #[test]
    fn prop_runlist_respects_total_size(
        fragments in prop::collection::vec((0u64..100, 10u64..50), 1..5),
        offset_delta in 0u64..100
    ) {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(&vec![0x99; 1000]).unwrap();
        temp_file.flush().unwrap();

        let inner_source = Arc::new(FileDataSource::new(temp_file.path().to_path_buf()).unwrap());

        let runs: Vec<(Option<u64>, u64)> = fragments.into_iter().map(|(offset, len)| (Some(offset), len)).collect();

        let runlist = RunListDataSource::from_allocation(inner_source, runs);

        let total_size = runlist.size();
        let offset = total_size + offset_delta;
        let mut buffer = vec![0u8; 50];

        let bytes_read = runlist.read_at(offset, &mut buffer).unwrap();

        prop_assert_eq!(bytes_read, 0,
            "RunListDataSource read beyond total_size {} should return 0", total_size);
    }
}

// Property: DataSource size() is consistent
proptest! {
    #[test]
    fn prop_datasource_size_consistent(data_size in 100usize..2000) {
        let test_data = vec![0x55; data_size];

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(&test_data).unwrap();
        temp_file.flush().unwrap();

        let source = FileDataSource::new(temp_file.path().to_path_buf()).unwrap();

        let size1 = source.size();
        let size2 = source.size();

        prop_assert_eq!(size1, size2, "DataSource size() should be consistent");
        prop_assert_eq!(size1, data_size as u64, "DataSource size() should match actual file size");
    }
}
