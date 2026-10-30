//! Synthetic inputs. They exercise header, bounds and emission handling only;
//! what a real cache decodes to is pinned in `tests/real_cache.rs`.

use super::*;
use seance_core::data_source::ByteSliceDataSource;

/// A cache with `tiles` tiles of `w` x `h`, pixel bytes set so each tile is a
/// distinct flat colour.
fn cache(tiles: usize, w: u16, h: u16) -> Vec<u8> {
    let mut v = cache_bin::MAGIC.to_vec();
    v.extend_from_slice(&4u32.to_le_bytes());
    for i in 0..tiles {
        v.extend_from_slice(&(i as u64 + 0x1111).to_le_bytes());
        v.extend_from_slice(&w.to_le_bytes());
        v.extend_from_slice(&h.to_le_bytes());
        for _ in 0..(w as usize * h as usize) {
            v.extend_from_slice(&[i as u8, 0x20, 0x40, 0x00]);
        }
    }
    v
}

fn run(name: &str, bytes: Vec<u8>) -> Vec<Artifact> {
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
    let a = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": name }),
    );
    RdpCacheParser::new().process(&a).unwrap()
}

fn of_type<'a>(out: &'a [Artifact], t: &str) -> Vec<&'a Artifact> {
    out.iter().filter(|a| a.metadata["type"] == t).collect()
}

#[test]
fn each_tile_becomes_a_png_file_the_gallery_can_list() {
    let out = run("Cache0000.bin", cache(3, 64, 64));
    let tiles = of_type(&out, "RdpCacheTile");
    assert_eq!(tiles.len(), 3, "{out:#?}");
    for (i, t) in tiles.iter().enumerate() {
        assert_eq!(t.artifact_type, ArtifactType::FileEntry);
        assert!(t.metadata["name"].as_str().unwrap().ends_with(".png"));
        assert_eq!(t.metadata["tile_index"], i);
        assert_eq!(
            t.metadata["key"],
            format!("{:016x}", (i as u64 + 0x1111).swap_bytes())
        );
        let ds = t.data.as_ref().expect("tile bytes");
        let mut sig = [0u8; 8];
        ds.read_at(0, &mut sig).unwrap();
        assert_eq!(&sig, b"\x89PNG\r\n\x1a\n");
    }
    let summary = of_type(&out, "RdpBitmapCache");
    assert_eq!(summary[0].metadata["tiles"], 3);
    assert!(summary[0].metadata.get("content_incomplete").is_none());
}

#[test]
fn the_collage_says_it_is_not_a_screen_reconstruction() {
    let out = run("Cache0001.bin", cache(2, 64, 64));
    let collages = of_type(&out, "RdpCacheCollage");
    assert_eq!(collages.len(), 1);
    assert_eq!(collages[0].metadata["collage_note"], COLLAGE_NOTE);
    assert!(collages[0].metadata["name"]
        .as_str()
        .unwrap()
        .ends_with(".png"));
}

#[test]
fn a_bad_magic_is_refused() {
    let mut bytes = cache(1, 64, 64);
    bytes[0] = b'X';
    let out = run("Cache0000.bin", bytes);
    assert_eq!(
        of_type(&out, "RdpBitmapCacheIncomplete").len(),
        1,
        "{out:#?}"
    );
    assert!(of_type(&out, "RdpCacheTile").is_empty());
}

#[test]
fn a_file_neither_named_nor_shaped_like_a_cache_is_left_alone() {
    assert!(run("photo.bin", vec![1, 2, 3, 4, 5, 6, 7, 8, 9]).is_empty());
}

#[test]
fn a_trailing_partial_tile_is_reported_incomplete() {
    let mut bytes = cache(2, 64, 64);
    bytes.truncate(bytes.len() - 100);
    let out = run("Cache0000.bin", bytes);
    assert_eq!(of_type(&out, "RdpCacheTile").len(), 1);
    let s = of_type(&out, "RdpBitmapCache");
    assert_eq!(s[0].metadata["content_incomplete"], true, "{out:#?}");
}

#[test]
fn a_tile_wider_than_64_is_refused_and_stops_the_walk() {
    let mut bytes = cache(2, 64, 64);
    // Second tile's width field.
    let at = cache_bin::HEADER_LEN + cache_bin::TILE_HEADER_LEN + 64 * 64 * 4 + 8;
    bytes[at..at + 2].copy_from_slice(&65u16.to_le_bytes());
    let out = run("Cache0000.bin", bytes);
    assert_eq!(of_type(&out, "RdpCacheTile").len(), 1);
    let s = of_type(&out, "RdpBitmapCache");
    assert!(s[0].metadata["content_incomplete_reason"]
        .as_str()
        .unwrap()
        .contains("65"));
}

#[test]
fn an_empty_bmc_reads_as_an_empty_cache_and_a_full_one_is_not_decoded() {
    let out = run("bcache24.bmc", Vec::new());
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].metadata["type"], "RdpBitmapCache");
    assert_eq!(out[0].metadata["tiles"], 0);
    assert_eq!(out[0].metadata["status"], "empty file (0 bytes)");

    let out = run("bcache22.bmc", vec![7u8; 4096]);
    assert_eq!(out[0].metadata["type"], "RdpBitmapCacheIncomplete");
    assert_eq!(out[0].metadata["status"], "NotDecoded");
}

/// Decode a PNG `FileEntry` into (width, height, RGB bytes).
fn decode_png(a: &Artifact) -> (u32, u32, Vec<u8>) {
    let ds = a.data.as_ref().expect("png bytes");
    let mut bytes = vec![0u8; ds.size() as usize];
    ds.read_at(0, &mut bytes).unwrap();
    let dec = png::Decoder::new(std::io::Cursor::new(bytes));
    let mut r = dec.read_info().unwrap();
    let mut buf = vec![0u8; r.output_buffer_size().unwrap()];
    let info = r.next_frame(&mut buf).unwrap();
    assert_eq!(info.color_type, png::ColorType::Rgb);
    buf.truncate(info.buffer_size());
    (info.width, info.height, buf)
}

/// Owner decision 2026-09-26 (§2.5, option a): every tile, plus **one**
/// collage per cache file, in cache order, labelled as not a reconstruction.
/// 1,025 tiles would have been split in two under the old 1,024-tile collage.
#[test]
fn one_collage_holds_every_tile_in_cache_order_and_says_it_is_not_a_reconstruction() {
    let n = 1_025usize;
    let out = run("Cache0000.bin", cache(n, 1, 1));
    let collages = of_type(&out, "RdpCacheCollage");
    assert_eq!(collages.len(), 1, "one collage per cache file");
    let c = &collages[0].metadata;
    assert_eq!(c["first_tile"], 0);
    assert_eq!(c["last_tile"], n - 1);
    assert_eq!(c["tiles_placed"], n);
    assert_eq!(c["reconstruction"], false);
    assert_eq!(c["columns"], COLLAGE_COLUMNS);
    assert!(
        c["collage_note"]
            .as_str()
            .unwrap()
            .starts_with("not a reconstruction"),
        "{c:#?}"
    );
    assert!(c["name"].as_str().unwrap().contains("not_a_reconstruction"));

    // The picture: 64 cells of 64 px across, rows enough for every tile, and
    // tile i in cell i counting left to right, top to bottom.
    let (w, h, rgb) = decode_png(collages[0]);
    let side = cache_bin::MAX_TILE_SIDE as usize;
    assert_eq!(w as usize, COLLAGE_COLUMNS * side);
    assert_eq!(h as usize, n.div_ceil(COLLAGE_COLUMNS) * side);
    let px = |i: usize| {
        let (cx, cy) = ((i % COLLAGE_COLUMNS) * side, (i / COLLAGE_COLUMNS) * side);
        let at = (cy * w as usize + cx) * 3;
        [rgb[at], rgb[at + 1], rgb[at + 2]]
    };
    for i in [0, 1, COLLAGE_COLUMNS - 1, COLLAGE_COLUMNS, 1_000, n - 1] {
        assert_eq!(px(i), [0x40, 0x20, i as u8], "cell {i}");
    }

    let summary = of_type(&out, "RdpBitmapCache");
    assert_eq!(summary[0].metadata["collages"], 1);
    assert_eq!(summary[0].metadata["tiles"], n);
}

/// A tile that cannot be read back leaves its cell blank and is counted, so
/// the collage never shifts later tiles into its place.
#[test]
fn an_unreadable_tile_leaves_its_cell_blank_and_later_tiles_keep_their_cells() {
    let bytes = cache(3, 1, 1);
    let len = bytes.len() as u64;
    let second_pixels = (cache_bin::HEADER_LEN + 16 + cache_bin::TILE_HEADER_LEN) as u64;
    let mut read = |off: u64, buf: &mut [u8]| -> usize {
        if off == second_pixels {
            return 0;
        }
        let end = (off as usize + buf.len()).min(bytes.len());
        let n = end.saturating_sub(off as usize);
        buf[..n].copy_from_slice(&bytes[off as usize..end]);
        n
    };
    let out =
        RdpCacheParser::records_for(Uuid::nil(), Uuid::nil(), "Cache0000.bin", len, &mut read);
    assert_eq!(of_type(&out, "RdpCacheTile").len(), 2);
    let collages = of_type(&out, "RdpCacheCollage");
    assert_eq!(collages.len(), 1);
    assert_eq!(collages[0].metadata["tiles_placed"], 2);
    assert_eq!(collages[0].metadata["cells_blank"], 1);
    let (w, _, rgb) = decode_png(collages[0]);
    assert_eq!(&rgb[64 * 3..64 * 3 + 3], &[0, 0, 0], "cell 1 blank");
    assert_eq!(
        &rgb[128 * 3..128 * 3 + 3],
        &[0x40, 0x20, 2],
        "tile 2 in cell 2"
    );
    assert_eq!(w as usize, 3 * 64);
    let s = of_type(&out, "RdpBitmapCache");
    assert_eq!(s[0].metadata["content_incomplete"], true);
}
