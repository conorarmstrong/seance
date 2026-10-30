//! Sectors and mini-sectors of an OLE compound file that its allocation
//! tables mark free.
//!
//! Read straight from the structures [MS-CFB] defines — the header, the DIFAT,
//! the FAT, the root directory entry and the mini-FAT — because the `cfb`
//! crate, which reads the live directory, does not expose its free maps. A
//! sector is free when its FAT entry is `FREESECT` (`0xFFFFFFFF`); a
//! mini-sector is free when its mini-FAT entry is, and it lies inside the
//! sectors the mini stream occupies. Deleting a stream frees its entries and
//! need not overwrite its bytes, so a freed stream's content can still be
//! there.
//!
//! Nothing here reads a directory entry other than the root's, and nothing
//! says which stream a freed sector belonged to: the allocation tables do not
//! record that.

const FREESECT: u32 = 0xFFFF_FFFF;
const ENDOFCHAIN: u32 = 0xFFFF_FFFE;
/// Bound on any chain walk, so a cycle in a hostile file ends.
const MAX_CHAIN: usize = 1 << 22;

/// A run of free space: where it is in the file, and which sectors it covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FreeRun {
    /// `"sector"` or `"mini_sector"`.
    pub kind: &'static str,
    /// The first sector (or mini-sector) index of the run.
    pub first_index: u32,
    /// The run's bytes, concatenated in allocation order.
    pub bytes: Vec<u8>,
    /// The file offset of each sector's first byte, in run order.
    pub sector_offsets: Vec<usize>,
    /// Bytes per sector in this run.
    pub sector_size: usize,
}

fn le16(b: &[u8], at: usize) -> Option<u16> {
    b.get(at..at + 2).map(|s| u16::from_le_bytes([s[0], s[1]]))
}

fn le32(b: &[u8], at: usize) -> Option<u32> {
    b.get(at..at + 4)
        .map(|s| u32::from_le_bytes(s.try_into().expect("4 bytes")))
}

struct Cfb<'a> {
    bytes: &'a [u8],
    shift: u32,
    fat: Vec<u32>,
}

impl<'a> Cfb<'a> {
    fn sector_size(&self) -> usize {
        1usize << self.shift
    }
    fn offset(&self, sector: u32) -> Option<usize> {
        (sector as usize)
            .checked_add(1)?
            .checked_mul(self.sector_size())
    }
    fn sector(&self, sector: u32) -> Option<&'a [u8]> {
        let off = self.offset(sector)?;
        self.bytes.get(off..off + self.sector_size())
    }
    /// Sectors in the file after the header.
    fn sectors_in_file(&self) -> usize {
        (self.bytes.len() / self.sector_size()).saturating_sub(1)
    }
    fn chain(&self, start: u32) -> Vec<u32> {
        let mut out = Vec::new();
        let mut seen = vec![false; self.fat.len()];
        let mut s = start;
        while s != ENDOFCHAIN && s != FREESECT && out.len() < MAX_CHAIN {
            // Past the table, or a sector already on the chain (a cycle).
            match seen.get_mut(s as usize) {
                Some(v) if !*v => *v = true,
                _ => break,
            }
            out.push(s);
            s = self.fat[s as usize];
        }
        out
    }
}

fn open(bytes: &[u8]) -> Result<Cfb<'_>, String> {
    const SIG: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
    if bytes.get(..8) != Some(&SIG[..]) {
        return Err("no compound-file signature".into());
    }
    let shift = le16(bytes, 0x1E).ok_or("header cut off")? as u32;
    if shift != 9 && shift != 12 {
        return Err(format!("sector shift {shift} is neither 9 nor 12"));
    }
    let mut cfb = Cfb {
        bytes,
        shift,
        fat: Vec::new(),
    };
    // FAT sector locations: 109 in the header, then the DIFAT chain.
    let mut fat_sectors: Vec<u32> = (0..109)
        .filter_map(|i| le32(bytes, 0x4C + i * 4))
        .filter(|&s| s != FREESECT && s != ENDOFCHAIN)
        .collect();
    let mut difat = le32(bytes, 0x44).ok_or("header cut off")?;
    let per = cfb.sector_size() / 4 - 1;
    let mut steps = 0usize;
    while difat != ENDOFCHAIN && difat != FREESECT && steps < MAX_CHAIN {
        let Some(sec) = cfb.sector(difat) else {
            return Err(format!(
                "DIFAT sector {difat} lies past the end of the file"
            ));
        };
        for i in 0..per {
            let s = le32(sec, i * 4).expect("inside the sector");
            if s != FREESECT && s != ENDOFCHAIN {
                fat_sectors.push(s);
            }
        }
        difat = le32(sec, per * 4).expect("inside the sector");
        steps += 1;
    }
    let mut fat = Vec::with_capacity(fat_sectors.len() * (cfb.sector_size() / 4));
    for s in fat_sectors {
        let Some(sec) = cfb.sector(s) else {
            return Err(format!("FAT sector {s} lies past the end of the file"));
        };
        fat.extend((0..cfb.sector_size() / 4).map(|i| le32(sec, i * 4).expect("inside")));
    }
    cfb.fat = fat;
    Ok(cfb)
}

/// Group consecutive indices into runs.
fn runs(indices: &[u32]) -> Vec<Vec<u32>> {
    let mut out: Vec<Vec<u32>> = Vec::new();
    for &i in indices {
        match out.last_mut() {
            Some(r) if r.last().map(|&l| l + 1) == Some(i) => r.push(i),
            _ => out.push(vec![i]),
        }
    }
    out
}

/// Every run of free sectors and free mini-sectors in `bytes`.
pub fn free_runs(bytes: &[u8]) -> Result<Vec<FreeRun>, String> {
    let cfb = open(bytes)?;
    let ss = cfb.sector_size();
    let mut out = Vec::new();

    // Regular sectors whose FAT entry is FREESECT and that the file holds.
    let limit = cfb.sectors_in_file().min(cfb.fat.len());
    let free: Vec<u32> = (0..limit as u32)
        .filter(|&i| cfb.fat[i as usize] == FREESECT)
        .collect();
    for run in runs(&free) {
        let mut data = Vec::with_capacity(run.len() * ss);
        let mut offsets = Vec::with_capacity(run.len());
        for &s in &run {
            if let (Some(sec), Some(off)) = (cfb.sector(s), cfb.offset(s)) {
                data.extend_from_slice(sec);
                offsets.push(off);
            }
        }
        out.push(FreeRun {
            kind: "sector",
            first_index: run[0],
            bytes: data,
            sector_offsets: offsets,
            sector_size: ss,
        });
    }

    // Mini-sectors: the mini stream is the root entry's stream.
    let mini_shift = le16(bytes, 0x20).unwrap_or(6) as u32;
    if !(1..=12).contains(&mini_shift) {
        return Ok(out);
    }
    let mini = 1usize << mini_shift;
    let first_dir = le32(bytes, 0x30).ok_or("header cut off")?;
    let Some(root) = cfb.sector(first_dir) else {
        return Ok(out);
    };
    let root_start = le32(root, 0x74).unwrap_or(ENDOFCHAIN);
    let stream_sectors = cfb.chain(root_start);
    let first_minifat = le32(bytes, 0x3C).unwrap_or(ENDOFCHAIN);
    let mut minifat: Vec<u32> = Vec::new();
    for s in cfb.chain(first_minifat) {
        if let Some(sec) = cfb.sector(s) {
            minifat.extend((0..ss / 4).map(|i| le32(sec, i * 4).expect("inside")));
        }
    }
    let slots = stream_sectors.len() * (ss / mini);
    let free_mini: Vec<u32> = (0..slots.min(minifat.len()) as u32)
        .filter(|&j| minifat[j as usize] == FREESECT)
        .collect();
    let file_offset = |j: u32| -> Option<usize> {
        let at = j as usize * mini;
        let sec = *stream_sectors.get(at / ss)?;
        Some(cfb.offset(sec)? + at % ss)
    };
    for run in runs(&free_mini) {
        let mut data = Vec::with_capacity(run.len() * mini);
        let mut offsets = Vec::with_capacity(run.len());
        for &j in &run {
            let Some(off) = file_offset(j) else { break };
            let Some(chunk) = bytes.get(off..off + mini) else {
                break;
            };
            data.extend_from_slice(chunk);
            offsets.push(off);
        }
        if !offsets.is_empty() {
            out.push(FreeRun {
                kind: "mini_sector",
                first_index: run[0],
                bytes: data,
                sector_offsets: offsets,
                sector_size: mini,
            });
        }
    }
    Ok(out)
}
