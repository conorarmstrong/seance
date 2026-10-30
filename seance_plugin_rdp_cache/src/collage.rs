//! The one collage a cache file gets: every tile, in the order the cache
//! stores it, [`COLUMNS`] cells across.
//!
//! It is written as a PNG one band of cells at a time — tiles arrive in cache
//! order, which is the collage's row-major order — so only one band's pixels
//! (at most 64 cells x 64 x 64 x 3 bytes, 768 KiB) are held however many tiles
//! the file has. Nothing here fits tile edges together: a cell's place says
//! where the tile sat in the file, never where it sat on the screen.

use std::cell::RefCell;
use std::io::Write;
use std::rc::Rc;

/// Where the encoder writes: shared so the bytes can be taken back after
/// `StreamWriter::finish`, which consumes the writer and returns nothing.
#[derive(Clone, Default)]
struct Sink(Rc<RefCell<Vec<u8>>>);

impl Write for Sink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.borrow_mut().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Cells across (4,096 px): the width `bmc-tools` uses for its collage.
pub const COLUMNS: usize = 64;
/// The side of a cell: no tile in either format is larger than 64 x 64.
pub const CELL: usize = 64;

/// A collage being written, one band of [`COLUMNS`] cells at a time.
pub struct Collage {
    cols: usize,
    band: Vec<u8>,
    in_band: usize,
    placed: usize,
    blank: usize,
    sink: Sink,
    writer: png::StreamWriter<'static, Sink>,
}

impl Collage {
    /// A collage for `tiles` tiles, or `None` when there are none (or the
    /// encoder refuses the dimensions).
    pub fn new(tiles: usize) -> Option<Self> {
        if tiles == 0 {
            return None;
        }
        let cols = COLUMNS.min(tiles);
        let rows = tiles.div_ceil(cols);
        let (w, h) = (
            u32::try_from(cols * CELL).ok()?,
            u32::try_from(rows * CELL).ok()?,
        );
        let sink = Sink::default();
        let mut enc = png::Encoder::new(sink.clone(), w, h);
        enc.set_color(png::ColorType::Rgb);
        enc.set_depth(png::BitDepth::Eight);
        let writer = enc.write_header().ok()?.into_stream_writer().ok()?;
        Some(Self {
            cols,
            band: vec![0u8; cols * CELL * CELL * 3],
            in_band: 0,
            placed: 0,
            blank: 0,
            sink,
            writer,
        })
    }

    /// Cells across.
    pub fn columns(&self) -> usize {
        self.cols
    }

    /// Put the next tile in the next cell: `Some((width, height, bgra))`, or
    /// `None` for a tile that could not be read, whose cell stays black so
    /// no later tile moves into its place.
    pub fn push(&mut self, tile: Option<(u16, u16, &[u8])>) -> Option<()> {
        let stride = self.cols * CELL * 3;
        match tile {
            Some((tw, th, px)) => {
                let (tw, th) = (tw as usize, th as usize);
                let cx = self.in_band * CELL;
                for y in 0..th.min(CELL) {
                    for x in 0..tw.min(CELL) {
                        let s = (y * tw + x) * 4;
                        let Some(p) = px.get(s..s + 3) else { continue };
                        let d = y * stride + (cx + x) * 3;
                        self.band[d..d + 3].copy_from_slice(&[p[2], p[1], p[0]]);
                    }
                }
                self.placed += 1;
            }
            None => self.blank += 1,
        }
        self.in_band += 1;
        if self.in_band == self.cols {
            self.flush_band()?;
        }
        Some(())
    }

    fn flush_band(&mut self) -> Option<()> {
        self.writer.write_all(&self.band).ok()?;
        self.band.fill(0);
        self.in_band = 0;
        Some(())
    }

    /// Finish the PNG. Returns `(png, tiles placed, cells left blank)`.
    pub fn finish(mut self) -> Option<(Vec<u8>, usize, usize)> {
        if self.in_band > 0 {
            self.flush_band()?;
        }
        let (placed, blank) = (self.placed, self.blank);
        self.writer.finish().ok()?;
        let png = self.sink.0.take();
        Some((png, placed, blank))
    }
}
