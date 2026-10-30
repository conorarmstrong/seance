//! DFIR Madness case 001 DC01's real `Cache0000.bin` (Server 2012 R2,
//! `Users/Administrator/AppData/Local/Microsoft/Terminal Server Client/Cache/`,
//! MFT entry 87133, 86,964,396 bytes). Not committed: the case's terms grant no
//! redistribution. `SEANCE_DC01_RDP_CACHE` is the file.

use seance_core::artifact::ArtifactType;
use seance_plugin_rdp_cache::{cache_bin, RdpCacheParser, COLLAGE_NOTE};
use std::io::{Read, Seek, SeekFrom};
use uuid::Uuid;

#[test]
fn dc01_cache0000_bin_yields_5304_tiles() {
    let Ok(path) = std::env::var("SEANCE_DC01_RDP_CACHE") else {
        eprintln!("SEANCE_DC01_RDP_CACHE unset; the DC01 cache check did not run");
        return;
    };
    let mut f = std::fs::File::open(&path).expect("open");
    let size = f.metadata().unwrap().len();
    assert_eq!(size, 86_964_396);
    let mut read = |off: u64, buf: &mut [u8]| -> usize {
        f.seek(SeekFrom::Start(off)).unwrap();
        let mut got = 0;
        while got < buf.len() {
            match f.read(&mut buf[got..]) {
                Ok(0) | Err(_) => break,
                Ok(n) => got += n,
            }
        }
        got
    };
    let out = RdpCacheParser::records_for(
        Uuid::new_v4(),
        Uuid::new_v4(),
        "Cache0000.bin",
        size,
        &mut read,
    );
    let tiles: Vec<_> = out
        .iter()
        .filter(|a| a.metadata["type"] == "RdpCacheTile")
        .collect();
    assert_eq!(tiles.len(), 5304);
    assert!(tiles
        .iter()
        .all(|t| t.artifact_type == ArtifactType::FileEntry
            && t.metadata["width"] == 64
            && t.metadata["height"] == 64
            && t.metadata["key"].as_str().unwrap().len() == 16));
    let collages: Vec<_> = out
        .iter()
        .filter(|a| a.metadata["type"] == "RdpCacheCollage")
        .collect();
    // Owner decision (a): one collage per cache file, labelled.
    assert_eq!(collages.len(), 1, "one collage holding all 5,304 tiles");
    let c = &collages[0].metadata;
    assert_eq!(c["collage_note"], COLLAGE_NOTE);
    assert_eq!(c["reconstruction"], false);
    assert_eq!(c["tiles_placed"], 5304);
    assert_eq!(c["first_tile"], 0);
    assert_eq!(c["last_tile"], 5303);
    assert_eq!(
        c["name"],
        "Cache0000_collage_cache_order_not_a_reconstruction.png"
    );
    // 64 cells across, 83 rows (5,304 / 64 rounded up), 64 px each.
    let ds = collages[0].data.as_ref().unwrap();
    let mut ihdr = [0u8; 24];
    ds.read_at(0, &mut ihdr).unwrap();
    assert_eq!(u32::from_be_bytes(ihdr[16..20].try_into().unwrap()), 4096);
    assert_eq!(
        u32::from_be_bytes(ihdr[20..24].try_into().unwrap()),
        83 * 64
    );
    let summary: Vec<_> = out
        .iter()
        .filter(|a| a.metadata["type"] == "RdpBitmapCache")
        .collect();
    assert_eq!(summary[0].metadata["version"], 4);
    assert_eq!(summary[0].metadata["tiles"], 5304);
    assert!(summary[0].metadata.get("content_incomplete").is_none());
    let _ = cache_bin::MAGIC;
}
