//! `Cache####.bin`, the `RDP8bmp` container.
//!
//! Measured on one real file (DFIR Madness case 001 DC01, version 4): a
//! 12-byte header — `RDP8bmp\0` and a u32 version — then tiles back to back,
//! each an 8-byte key, a u16 width, a u16 height and `width x height` pixels of
//! four bytes, blue-green-red then a fourth byte that is zero on every pixel of
//! that file and is not used. 86,964,396 bytes held exactly 5,304 64 x 64
//! tiles.

/// The container's magic, `RDP8bmp` and a NUL.
pub const MAGIC: &[u8; 8] = b"RDP8bmp\0";
/// Header: magic and a u32 version.
pub const HEADER_LEN: usize = 12;
/// Per tile: an 8-byte key, u16 width, u16 height.
pub const TILE_HEADER_LEN: usize = 12;
/// No tile in this cache is larger than 64 x 64.
pub const MAX_TILE_SIDE: u16 = 64;

/// One tile as the walk found it; its pixels are at `pixels_offset`.
#[derive(Debug, Clone, PartialEq)]
pub struct Tile {
    pub index: usize,
    pub offset: u64,
    pub key: [u8; 8],
    pub width: u16,
    pub height: u16,
    pub pixels_offset: u64,
}

/// The walk's result.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CacheWalk {
    pub version: u32,
    pub tiles: Vec<Tile>,
    /// Why the walk stopped before the end of the file, when it did.
    pub incomplete: Option<String>,
}

/// Why a file was not walked at all.
#[derive(Debug, Clone, PartialEq)]
pub enum Refusal {
    BadMagic,
    TooShort,
}

/// Walk the tile headers. `read(offset, buf)` fills `buf` from the file and
/// returns how many bytes it read.
pub fn walk(
    size: u64,
    read: &mut dyn FnMut(u64, &mut [u8]) -> usize,
    max_tiles: usize,
) -> Result<CacheWalk, Refusal> {
    let mut head = [0u8; HEADER_LEN];
    if size < HEADER_LEN as u64 || read(0, &mut head) != HEADER_LEN {
        return Err(Refusal::TooShort);
    }
    if &head[..8] != MAGIC {
        return Err(Refusal::BadMagic);
    }
    let mut out = CacheWalk {
        version: u32::from_le_bytes(head[8..12].try_into().expect("4 bytes")),
        ..Default::default()
    };
    let mut p = HEADER_LEN as u64;
    while p < size {
        let index = out.tiles.len();
        if index >= max_tiles {
            out.incomplete = Some(format!(
                "the walk stops at the {max_tiles}-tile cap; {} bytes from offset {p} were not read",
                size - p
            ));
            break;
        }
        let mut th = [0u8; TILE_HEADER_LEN];
        if size - p < TILE_HEADER_LEN as u64 || read(p, &mut th) != TILE_HEADER_LEN {
            out.incomplete = Some(format!(
                "{} trailing byte(s) at offset {p} are too few for a tile header",
                size - p
            ));
            break;
        }
        let key: [u8; 8] = th[..8].try_into().expect("8 bytes");
        let width = u16::from_le_bytes([th[8], th[9]]);
        let height = u16::from_le_bytes([th[10], th[11]]);
        if width == 0 || height == 0 || width > MAX_TILE_SIDE || height > MAX_TILE_SIDE {
            out.incomplete = Some(format!(
                "tile {index} at offset {p} declares {width} x {height}; a tile is 1 to \
                 {MAX_TILE_SIDE} pixels a side, so the walk stops here"
            ));
            break;
        }
        let pixels = width as u64 * height as u64 * 4;
        let pixels_offset = p + TILE_HEADER_LEN as u64;
        if size - pixels_offset < pixels {
            out.incomplete = Some(format!(
                "tile {index} at offset {p} needs {pixels} pixel bytes and the file holds {}; \
                 the partial tile is not emitted",
                size - pixels_offset
            ));
            break;
        }
        out.tiles.push(Tile {
            index,
            offset: p,
            key,
            width,
            height,
            pixels_offset,
        });
        p = pixels_offset + pixels;
    }
    Ok(out)
}

/// Blue-green-red-unused pixels to an 8-bit RGB PNG of `width` x `height`.
pub fn tile_png(bgra: &[u8], width: u16, height: u16) -> Option<Vec<u8>> {
    let n = width as usize * height as usize;
    if bgra.len() < n * 4 {
        return None;
    }
    let rgb: Vec<u8> = bgra[..n * 4]
        .as_chunks::<4>()
        .0
        .iter()
        .flat_map(|p| [p[2], p[1], p[0]])
        .collect();
    rgb_png(&rgb, width as u32, height as u32)
}

/// An 8-bit RGB buffer to PNG.
pub fn rgb_png(rgb: &[u8], width: u32, height: u32) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    {
        let mut enc = png::Encoder::new(&mut out, width, height);
        enc.set_color(png::ColorType::Rgb);
        enc.set_depth(png::BitDepth::Eight);
        let mut w = enc.write_header().ok()?;
        w.write_image_data(rgb).ok()?;
    }
    Some(out)
}
