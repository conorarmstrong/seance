use crate::data_source::{DataSource, RunListDataSource, WindowSource};
use std::io::Result;
use std::sync::Arc;

// Mock DataSource for testing
#[derive(Debug)]
struct MockDataSource {
    data: Vec<u8>,
}

impl MockDataSource {
    #[allow(dead_code)]
    fn new(size: usize, pattern: u8) -> Self {
        Self {
            data: vec![pattern; size],
        }
    }

    fn new_with_data(data: Vec<u8>) -> Self {
        Self { data }
    }
}

impl DataSource for MockDataSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        if offset >= self.data.len() as u64 {
            return Ok(0);
        }
        let remaining = self.data.len() as u64 - offset;
        let to_read = std::cmp::min(remaining, buf.len() as u64) as usize;
        buf[..to_read].copy_from_slice(&self.data[offset as usize..offset as usize + to_read]);
        Ok(to_read)
    }

    fn size(&self) -> u64 {
        self.data.len() as u64
    }
}

#[test]
fn test_window_source() {
    let inner = Arc::new(MockDataSource::new_with_data(vec![
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
    ]));
    let window = WindowSource::new(inner, 2, 5); // Window from index 2, length 5 (2,3,4,5,6)

    assert_eq!(window.size(), 5);

    let mut buf = vec![0u8; 3];

    // Read beginning
    let n = window.read_at(0, &mut buf).unwrap();
    assert_eq!(n, 3);
    assert_eq!(buf, vec![2, 3, 4]);

    // Read crossing boundary
    let n = window.read_at(3, &mut buf).unwrap();
    assert_eq!(n, 2); // Should only get 2 bytes (5, 6)
    assert_eq!(buf[..2], vec![5, 6]);

    // Read past end
    let n = window.read_at(10, &mut buf).unwrap();
    assert_eq!(n, 0);
}

#[test]
fn test_run_list_source() {
    let inner = Arc::new(MockDataSource::new_with_data(vec![
        0xAA, 0xAA, 0xAA, // 0-2
        0xBB, 0xBB, // 3-4
        0xCC, 0xCC, 0xCC, // 5-7
    ]));

    // Run 1: Offset 0 (AA AA AA), Length 3
    // Run 2: Sparse (Zeros), Length 2
    // Run 3: Offset 5 (CC CC CC), Length 3
    let runs = vec![(Some(0), 3), (None, 2), (Some(5), 3)];

    let source = RunListDataSource::from_allocation(inner, runs);
    assert_eq!(source.size(), 8);

    let mut buf = vec![0u8; 8];
    let n = source.read_at(0, &mut buf).unwrap();
    assert_eq!(n, 8);
    assert_eq!(
        buf,
        vec![
            0xAA, 0xAA, 0xAA, // Run 1
            0x00, 0x00, // Run 2 (Sparse)
            0xCC, 0xCC, 0xCC // Run 3
        ]
    );
}

#[test]
fn test_run_list_short_inner_read_not_counted() {
    let inner = Arc::new(MockDataSource::new_with_data(vec![1, 2, 3, 4]));
    // Run claims 8 bytes at physical offset 0, but the inner source only has 4.
    let runs = vec![(Some(0), 8)];
    let source = RunListDataSource::from_allocation(inner, runs);

    let mut buf = vec![0xFFu8; 8];
    let n = source.read_at(0, &mut buf).unwrap();
    assert_eq!(n, 4, "must not count bytes the inner source never wrote");
    assert_eq!(&buf[..4], &[1, 2, 3, 4]);
}

#[test]
fn test_run_list_short_inner_read_stops_before_later_runs() {
    let inner = Arc::new(MockDataSource::new_with_data(vec![1, 2, 3, 4]));
    // First run is truncated by the inner source; a sparse run follows.
    let runs = vec![(Some(2), 4), (None, 4)];
    let source = RunListDataSource::from_allocation(inner, runs);

    let mut buf = vec![0xFFu8; 8];
    let n = source.read_at(0, &mut buf).unwrap();
    assert_eq!(
        n, 2,
        "short read mid-run must stop, not skip ahead to later runs"
    );
    assert_eq!(&buf[..2], &[3, 4]);
}

#[test]
fn test_run_list_fragmented_read() {
    let inner = Arc::new(MockDataSource::new_with_data(vec![1, 2, 3, 4, 5, 6]));
    // Virtual: [1, 2] [0, 0] [5, 6]
    let runs = vec![
        (Some(0), 2), // 1, 2
        (None, 2),    // 0, 0
        (Some(4), 2), // 5, 6
    ];
    let source = RunListDataSource::from_allocation(inner, runs);

    let mut buf = vec![0u8; 4];
    // Read offset 1: should get [2, 0, 0, 5]
    let n = source.read_at(1, &mut buf).unwrap();
    assert_eq!(n, 4);
    assert_eq!(buf, vec![2, 0, 0, 5]);
}

// ─── Extent source labelling ────────────────────────────────────────────────
//
// A swapped-out page has real bytes at a real offset in a *different file* from
// the evidence image. These cover the machinery that lets a projection say so
// without ever handing an examiner an offset to read against the wrong source.

mod extent_source {
    use crate::data_source::{ExtentPrecision, ExtentSource, PhysicalExtent, PhysicalMap};

    #[test]
    fn an_ordinary_extent_is_on_the_device() {
        let extent = PhysicalExtent::device(4096, 512);
        assert_eq!(extent.source, ExtentSource::Device);
        assert!(!extent.is_auxiliary());
        assert_eq!(extent.device_offset, Some(4096));
    }

    #[test]
    fn a_hole_has_no_offset_and_is_not_auxiliary() {
        let hole = PhysicalExtent::hole(4096);
        assert_eq!(hole.device_offset, None);
        assert!(!hole.is_auxiliary());
    }

    #[test]
    fn an_auxiliary_extent_carries_its_offset_and_its_source() {
        let extent = PhysicalExtent::auxiliary(2, 0x3F2000, 4096);
        assert!(extent.is_auxiliary());
        assert_eq!(extent.device_offset, Some(0x3F2000));
        assert_eq!(extent.source, ExtentSource::Auxiliary(2));
    }

    #[test]
    fn interning_the_same_source_twice_reuses_one_index() {
        // Otherwise a file fragmented across a thousand swapped pages would
        // carry a thousand copies of the same pagefile name.
        let mut map = PhysicalMap::empty(ExtentPrecision::Exact);
        let first = map.intern_auxiliary("pagefile.sys").expect("first fits");
        let again = map.intern_auxiliary("pagefile.sys").expect("second fits");
        let other = map.intern_auxiliary("swapfile.sys").expect("third fits");
        assert_eq!(first, again);
        assert_ne!(first, other);
        assert_eq!(map.auxiliary_sources.len(), 2);
    }

    /// The bug `absorb` exists to prevent.
    ///
    /// Two nested projections each number their own sources from zero. Merging
    /// their extent lists without rebasing would leave an extent that says
    /// "auxiliary 0" pointing at whichever file happened to be first in the
    /// parent — a real offset, in a real file, confidently the wrong one.
    #[test]
    fn absorbing_a_map_rebases_its_auxiliary_indices() {
        let mut outer = PhysicalMap::empty(ExtentPrecision::Exact);
        let outer_idx = outer.intern_auxiliary("outer-pagefile.sys").unwrap();
        outer
            .extents
            .push(PhysicalExtent::auxiliary(outer_idx, 0x1000, 4096));

        // The inner map numbers its own source 0 — the same number the outer
        // map already uses for a different file.
        let mut inner = PhysicalMap::empty(ExtentPrecision::Exact);
        let inner_idx = inner.intern_auxiliary("inner-swapfile.sys").unwrap();
        assert_eq!(inner_idx, 0, "the collision this test is about");
        inner
            .extents
            .push(PhysicalExtent::auxiliary(inner_idx, 0x2000, 4096));

        outer.absorb(inner);

        assert_eq!(outer.extents.len(), 2);
        let names: Vec<&str> = outer
            .extents
            .iter()
            .map(|e| match e.source {
                ExtentSource::Auxiliary(i) => outer.auxiliary_sources[i as usize].as_str(),
                ExtentSource::Device => "device",
            })
            .collect();
        assert_eq!(
            names,
            vec!["outer-pagefile.sys", "inner-swapfile.sys"],
            "each extent must still name the file it actually came from"
        );
    }

    #[test]
    fn absorbing_deduplicates_a_source_both_maps_name() {
        let mut outer = PhysicalMap::empty(ExtentPrecision::Exact);
        let a = outer.intern_auxiliary("pagefile.sys").unwrap();
        outer.extents.push(PhysicalExtent::auxiliary(a, 0, 4096));

        let mut inner = PhysicalMap::empty(ExtentPrecision::Exact);
        let b = inner.intern_auxiliary("pagefile.sys").unwrap();
        inner.extents.push(PhysicalExtent::auxiliary(b, 4096, 4096));

        outer.absorb(inner);
        assert_eq!(
            outer.auxiliary_sources.len(),
            1,
            "one file named twice is still one file"
        );
        assert!(outer
            .extents
            .iter()
            .all(|e| e.source == ExtentSource::Auxiliary(0)));
    }

    /// An index with no name behind it must not degrade into a device offset.
    #[test]
    fn a_dangling_auxiliary_index_becomes_unlocated_not_a_device_offset() {
        let mut outer = PhysicalMap::empty(ExtentPrecision::Exact);

        // A malformed inner map: an extent refers to source 3, but the table
        // names none. Reporting 0x2000 as a device offset here would send an
        // examiner to that offset in the evidence image.
        let mut inner = PhysicalMap::empty(ExtentPrecision::Exact);
        inner
            .extents
            .push(PhysicalExtent::auxiliary(3, 0x2000, 4096));

        outer.absorb(inner);

        let extent = outer.extents[0];
        assert_eq!(
            extent.device_offset, None,
            "bytes we cannot locate must be reported as unlocated"
        );
        assert_eq!(extent.source, ExtentSource::Device);
        assert_eq!(
            outer.precision,
            ExtentPrecision::Synthetic,
            "losing a location degrades the projection's precision"
        );
    }

    #[test]
    fn absorbing_takes_the_worse_precision_of_the_two() {
        let mut outer = PhysicalMap::empty(ExtentPrecision::Exact);
        outer.absorb(PhysicalMap::empty(ExtentPrecision::Compressed));
        assert_eq!(outer.precision, ExtentPrecision::Compressed);
    }

    #[test]
    fn a_device_only_map_names_no_auxiliary_sources() {
        // The ordinary case must stay clean: nothing to explain, nothing listed.
        let map = PhysicalMap::exact(512, 4096);
        assert!(map.auxiliary_sources.is_empty());
        assert!(map.extents.iter().all(|e| !e.is_auxiliary()));
    }
}

/// Wraps a source and fails every read while `failing` is set.
#[derive(Debug)]
struct SwitchableSource {
    inner: MockDataSource,
    failing: std::sync::atomic::AtomicBool,
}

impl DataSource for SwitchableSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        if self.failing.load(std::sync::atomic::Ordering::SeqCst) {
            // Scribble on the buffer first, as a half-completed read would.
            buf.fill(0xEE);
            return Err(std::io::Error::other("injected read failure"));
        }
        self.inner.read_at(offset, buf)
    }

    fn size(&self) -> u64 {
        self.inner.size()
    }
}

#[test]
fn a_failed_buffered_refill_does_not_leave_zeros_to_be_served_from_the_old_window() {
    use crate::data_source::BufferedDataSource;
    use std::sync::atomic::Ordering;

    let data: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
    let inner = Arc::new(SwitchableSource {
        inner: MockDataSource::new_with_data(data.clone()),
        failing: std::sync::atomic::AtomicBool::new(false),
    });
    let buffered = BufferedDataSource::new(inner.clone(), 1024);

    // Fill the cache window [0, 1024).
    let mut b = [0u8; 16];
    assert_eq!(buffered.read_at(0, &mut b).unwrap(), 16);
    assert_eq!(&b[..], &data[..16]);

    // A read spanning the window end falls through to a refill, which fails.
    inner.failing.store(true, Ordering::SeqCst);
    let mut wide = [0u8; 64];
    assert!(buffered.read_at(1000, &mut wide).is_err());

    // The old window must not answer from its zero-extended remains.
    let mut again = [0u8; 16];
    let r = buffered.read_at(512, &mut again);
    assert!(r.is_err(), "served {again:?} from a failed refill");

    // Once the source recovers, real bytes come back.
    inner.failing.store(false, Ordering::SeqCst);
    assert_eq!(buffered.read_at(512, &mut again).unwrap(), 16);
    assert_eq!(&again[..], &data[512..528]);
}
