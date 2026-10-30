//! Native, bounds-checked Windows Prefetch (`.pf` / SCCA) parser.
//!
//! Replaces the previous unmaintained third-party parser, whose metric parser
//! did an unbounded `Vec::with_capacity(n)` on an attacker-controlled count (a
//! 267-byte file could drive a ~270 GB allocation). Here every count and offset
//! read from the file is validated against the actual buffer length before it is
//! used to slice or allocate, so no malformed input can panic, OOM, or hang.
//!
//! Supported on-disk formats:
//! - v17 (Windows XP / 2003)
//! - v23 (Windows Vista / 7)
//! - v26 (Windows 8 / 8.1)
//! - v30 (Windows 10) and v31 (Windows 11) uncompressed SCCA
//! - MAM (`MAM\x04`) Xpress-Huffman compressed wrapper used by Windows 10/11:
//!   the compressed blob is decompressed via the pure-Rust, panic-free
//!   `xpress-huffman` crate, then parsed as SCCA.
//!
//! Field offsets and section layouts mirror the previous third-party parser's
//! behaviour so downstream artifact consumers see identical output for the
//! versions it supported (v17/v23/v26). v30/v31 previously yielded nothing (the
//! old parser returned `NotImplemented`); they are now parsed too.

/// "SCCA" signature at file offset 4 of an uncompressed prefetch file.
const SCCA_SIG: [u8; 4] = [0x53, 0x43, 0x43, 0x41];
/// "MAM\x04" wrapper magic for Xpress-Huffman compressed Win10/11 prefetch.
const MAM_SIG: [u8; 4] = [b'M', b'A', b'M', 0x04];

/// Generous absolute ceiling on the declared metric count. Real prefetch files
/// reference at most a few thousand loaded files.
const MAX_METRICS: usize = 1_000_000;
/// Real prefetch files have one to a handful of volumes.
const MAX_VOLUMES: usize = 10_000;

/// A single referenced volume, matching the fields the module emits.
#[derive(Debug, Clone)]
pub(crate) struct VolumeInfo {
    pub device_path: String,
    pub creation_time: u64,
    pub serial_number: u32,
}

/// Parsed prefetch record: exactly the fields the module turns into an artifact.
#[derive(Debug, Clone)]
pub(crate) struct ParsedPrefetch {
    pub executable_name: String,
    pub run_count: u64,
    pub last_execution_time: u64,
    /// Non-zero last-run FILETIMEs, most-recent first. Windows 8+ (v26/30/31)
    /// records up to 8; earlier versions record a single time.
    pub run_times: Vec<u64>,
    pub volumes: Vec<VolumeInfo>,
    pub loaded_files: Vec<String>,
    /// Human-readable version label, identical to the previous parser's
    /// `FormatVersion` `Debug` output for the versions it supported.
    pub version_label: &'static str,
}

/// Parse failure reasons. Every variant is a clean, recoverable error: the
/// caller logs it and produces no artifact rather than crashing.
#[derive(Debug)]
pub(crate) enum PrefetchError {
    /// File is shorter than a required fixed field.
    TooShort,
    /// Missing "SCCA" signature at offset 4.
    NotScca,
    /// Version code is not a recognised prefetch format.
    UnknownVersion(u32),
    /// A declared section offset/length runs past the end of the file.
    SectionOutOfBounds,
    /// A declared entry count exceeds the sane ceiling for its section.
    CountTooLarge,
    /// Offset arithmetic overflowed (a lie in the header).
    ArithmeticOverflow,
    /// MAM declared an uncompressed size of zero or beyond the accepted cap.
    CompressedSizeImplausible(usize),
    /// The Xpress-Huffman blob could not be decompressed.
    Decompress(xpress_huffman::Error),
}

impl std::fmt::Display for PrefetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PrefetchError::TooShort => write!(f, "file too short for prefetch header"),
            PrefetchError::NotScca => write!(f, "missing SCCA signature"),
            PrefetchError::UnknownVersion(v) => write!(f, "unknown prefetch version {v}"),
            PrefetchError::SectionOutOfBounds => {
                write!(f, "declared section extends past end of file")
            }
            PrefetchError::CountTooLarge => write!(f, "declared entry count is implausibly large"),
            PrefetchError::ArithmeticOverflow => write!(f, "offset arithmetic overflow"),
            PrefetchError::CompressedSizeImplausible(n) => {
                write!(f, "implausible MAM uncompressed size {n}")
            }
            PrefetchError::Decompress(e) => write!(f, "MAM decompression failed: {e}"),
        }
    }
}

/// Version-specific field offsets and section entry sizes.
struct Layout {
    label: &'static str,
    /// Absolute file offset of the most-recent last-run FILETIME (u64 LE).
    /// Windows 8+ stores an array of `run_times_count` consecutive FILETIMEs
    /// starting here.
    last_exec_off: usize,
    /// Number of consecutive last-run FILETIME slots at `last_exec_off`.
    run_times_count: usize,
    /// Absolute file offset of the run counter (u32 LE).
    run_count_off: usize,
    /// Alternate run-counter offset for versions whose on-disk layout has two
    /// known variants under the same version number (Windows 10 1607+ moved
    /// RunCount from 0xD0 to 0xC8). `None` when the offset is unambiguous.
    run_count_off_alt: Option<usize>,
    /// Size in bytes of one file-metrics entry.
    metric_entry_size: usize,
    /// Byte offset within a metrics entry of the filename-string offset (u32 LE).
    metric_name_off: usize,
    /// Byte offset within a metrics entry of the filename-string length (u32 LE).
    metric_len_off: usize,
    /// Size in bytes of one volume-information entry.
    volume_entry_size: usize,
}

fn layout_for(version: u32) -> Option<Layout> {
    Some(match version {
        17 => Layout {
            label: "WindowsXp2003",
            last_exec_off: 0x78,
            run_times_count: 1,
            run_count_off: 0x90,
            run_count_off_alt: None,
            metric_entry_size: 20,
            metric_name_off: 0x8,
            metric_len_off: 0xc,
            volume_entry_size: 40,
        },
        23 => Layout {
            label: "WindowsVista7",
            last_exec_off: 0x80,
            run_times_count: 1,
            run_count_off: 0x98,
            run_count_off_alt: None,
            metric_entry_size: 32,
            metric_name_off: 0xc,
            metric_len_off: 0x10,
            volume_entry_size: 104,
        },
        26 => Layout {
            label: "Windows8",
            last_exec_off: 0x80,
            run_times_count: 8,
            run_count_off: 0xd0,
            run_count_off_alt: None,
            metric_entry_size: 32,
            metric_name_off: 0xc,
            metric_len_off: 0x10,
            volume_entry_size: 104,
        },
        30 => Layout {
            label: "Windows10",
            last_exec_off: 0x80,
            run_times_count: 8,
            run_count_off: 0xd0,
            run_count_off_alt: Some(0xc8),
            metric_entry_size: 32,
            metric_name_off: 0xc,
            metric_len_off: 0x10,
            volume_entry_size: 96,
        },
        31 => Layout {
            label: "Windows11",
            last_exec_off: 0x80,
            run_times_count: 8,
            run_count_off: 0xd0,
            run_count_off_alt: Some(0xc8),
            metric_entry_size: 32,
            metric_name_off: 0xc,
            metric_len_off: 0x10,
            volume_entry_size: 96,
        },
        _ => return None,
    })
}

/// Read the run counter, disambiguating the two Windows 10 v30/v31 layouts.
///
/// Windows 10 build 1607 moved RunCount from 0xD0 to 0xC8 without changing the
/// version number, so the offset cannot be inferred from the version alone
/// (PECmd and other tools disambiguate structurally). A prefetch file records
/// at least one execution, so the true count is a small positive number: pick
/// the canonical offset when it holds a plausible count, otherwise fall back to
/// the alternate. This never worsens a correctly laid-out 0xD0 file (its
/// canonical field is already valid) and recovers the count for 1607+ files,
/// whose 0xD0 position holds an unrelated field (commonly zero).
fn read_run_count(data: &[u8], layout: &Layout) -> Result<u64, PrefetchError> {
    /// Real prefetch run counts are modest; a value past this is not a count.
    const MAX_PLAUSIBLE_RUN_COUNT: u32 = 1_000_000;
    let is_plausible = |c: u32| (1..=MAX_PLAUSIBLE_RUN_COUNT).contains(&c);

    let primary = u32_le(data, layout.run_count_off)?;
    match layout.run_count_off_alt {
        Some(alt_off) => {
            let alt = u32_le(data, alt_off)?;
            if !is_plausible(primary) && is_plausible(alt) {
                Ok(alt as u64)
            } else {
                Ok(primary as u64)
            }
        }
        None => Ok(primary as u64),
    }
}

/// Read a little-endian u32 at `off`, or `Err` if the file is too short.
fn u32_le(data: &[u8], off: usize) -> Result<u32, PrefetchError> {
    let end = off
        .checked_add(4)
        .ok_or(PrefetchError::ArithmeticOverflow)?;
    let s = data.get(off..end).ok_or(PrefetchError::TooShort)?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// Read a little-endian u64 at `off`, or `Err` if the file is too short.
fn u64_le(data: &[u8], off: usize) -> Result<u64, PrefetchError> {
    let end = off
        .checked_add(8)
        .ok_or(PrefetchError::ArithmeticOverflow)?;
    let s = data.get(off..end).ok_or(PrefetchError::TooShort)?;
    Ok(u64::from_le_bytes([
        s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
    ]))
}

/// Decode the fixed 60-byte UTF-16LE executable-name field, stopping at the
/// first NUL (max 30 code units).
fn read_name(field: &[u8]) -> String {
    let mut units = Vec::new();
    let mut i = 0;
    while i + 1 < field.len() && units.len() < 30 {
        let u = u16::from_le_bytes([field[i], field[i + 1]]);
        if u == 0 {
            break;
        }
        units.push(u);
        i += 2;
    }
    String::from_utf16_lossy(&units)
}

/// Read a NUL-terminated UTF-16LE string from `section` starting at `byte_off`,
/// reading at most `max_units` code units. Fully bounds-checked: it never reads
/// past the end of `section`.
///
/// The cap is in UTF-16 code units, so the available room has to be converted
/// from bytes before comparing (B6-034): capping a unit count with a byte length
/// cut names short whenever the section was smaller than the declared length,
/// and a shortened path is a different file from the one the record names.
pub(crate) fn read_utf16_string(section: &[u8], byte_off: usize, max_units: usize) -> String {
    let units_available = section.len().saturating_sub(byte_off) / 2;
    let cap = max_units.min(units_available);
    let mut units = Vec::new();
    let mut i = byte_off;
    while units.len() < cap {
        let (lo, hi) = match (section.get(i), section.get(i + 1)) {
            (Some(&lo), Some(&hi)) => (lo, hi),
            _ => break,
        };
        let u = u16::from_le_bytes([lo, hi]);
        if u == 0 {
            break;
        }
        units.push(u);
        i += 2;
    }
    String::from_utf16_lossy(&units)
}

/// Extract the referenced-file list from the metrics array, matching
/// the previous parser's per-entry filename lookup.
fn parse_metrics(data: &[u8], layout: &Layout) -> Result<Vec<String>, PrefetchError> {
    let metrics_offset = u32_le(data, 0x54)? as usize;
    let count = u32_le(data, 0x58)? as usize;
    if count > MAX_METRICS {
        return Err(PrefetchError::CountTooLarge);
    }

    let section_len = count
        .checked_mul(layout.metric_entry_size)
        .ok_or(PrefetchError::ArithmeticOverflow)?;
    let section_end = metrics_offset
        .checked_add(section_len)
        .ok_or(PrefetchError::ArithmeticOverflow)?;
    let section = data
        .get(metrics_offset..section_end)
        .ok_or(PrefetchError::SectionOutOfBounds)?;

    let name_offset = u32_le(data, 0x64)? as usize;
    let name_size = u32_le(data, 0x68)? as usize;
    let name_end = name_offset
        .checked_add(name_size)
        .ok_or(PrefetchError::ArithmeticOverflow)?;
    let name_section = data
        .get(name_offset..name_end)
        .ok_or(PrefetchError::SectionOutOfBounds)?;

    let mut files = Vec::with_capacity(count.min(1024));
    for i in 0..count {
        let start = i * layout.metric_entry_size;
        let entry = section
            .get(start..start + layout.metric_entry_size)
            .ok_or(PrefetchError::SectionOutOfBounds)?;
        let str_off = u32_le(entry, layout.metric_name_off)? as usize;
        let str_len = u32_le(entry, layout.metric_len_off)? as usize;
        files.push(read_utf16_string(name_section, str_off, str_len));
    }
    Ok(files)
}

/// Extract the referenced volume(s): device path, serial, creation time.
/// Directory entries are intentionally skipped (the module does not emit them).
fn parse_volumes(data: &[u8], layout: &Layout) -> Result<Vec<VolumeInfo>, PrefetchError> {
    let vol_offset = u32_le(data, 0x6c)? as usize;
    let count = u32_le(data, 0x70)? as usize;
    if count > MAX_VOLUMES {
        return Err(PrefetchError::CountTooLarge);
    }

    let section = data
        .get(vol_offset..)
        .ok_or(PrefetchError::SectionOutOfBounds)?;

    let mut volumes = Vec::with_capacity(count.min(256));
    for i in 0..count {
        let start = i
            .checked_mul(layout.volume_entry_size)
            .ok_or(PrefetchError::ArithmeticOverflow)?;
        let end = start
            .checked_add(layout.volume_entry_size)
            .ok_or(PrefetchError::ArithmeticOverflow)?;
        let entry = section
            .get(start..end)
            .ok_or(PrefetchError::SectionOutOfBounds)?;

        let dp_offset = u32_le(entry, 0x0)? as usize;
        let dp_chars = u32_le(entry, 0x4)? as usize;
        volumes.push(VolumeInfo {
            device_path: read_utf16_string(section, dp_offset, dp_chars),
            creation_time: u64_le(entry, 0x8)?,
            serial_number: u32_le(entry, 0x10)?,
        });
    }
    Ok(volumes)
}

/// Parse an uncompressed SCCA prefetch buffer.
fn parse_scca(data: &[u8]) -> Result<ParsedPrefetch, PrefetchError> {
    let version = u32_le(data, 0)?;
    if data.get(4..8) != Some(&SCCA_SIG[..]) {
        return Err(PrefetchError::NotScca);
    }
    let layout = layout_for(version).ok_or(PrefetchError::UnknownVersion(version))?;

    let name_field = data.get(0x10..0x4c).ok_or(PrefetchError::TooShort)?;
    let executable_name = read_name(name_field);

    // The primary last-run FILETIME must be present; it also seeds run_times.
    let last_execution_time = u64_le(data, layout.last_exec_off)?;
    let mut run_times = Vec::new();
    if last_execution_time != 0 {
        run_times.push(last_execution_time);
    }
    // Windows 8+ records up to 8 last-run times; collect the remaining non-zero
    // slots. A slot that runs past the end of the buffer stops collection rather
    // than failing here -- but it cannot produce a short, complete-looking
    // history: `read_run_count` below reads a field that sits *after* the whole
    // last-run array in every supported layout, so a buffer too short for a slot
    // is also too short for the run counter and the parse fails closed.
    for i in 1..layout.run_times_count {
        let off = match layout.last_exec_off.checked_add(i * 8) {
            Some(o) => o,
            None => break,
        };
        match u64_le(data, off) {
            Ok(t) if t != 0 => run_times.push(t),
            Ok(_) => {}      // zero = unused slot, keep scanning
            Err(_) => break, // truncated; read_run_count rejects the file
        }
    }

    let run_count = read_run_count(data, &layout)?;

    let loaded_files = parse_metrics(data, &layout)?;
    let volumes = parse_volumes(data, &layout)?;

    Ok(ParsedPrefetch {
        executable_name,
        run_count,
        last_execution_time,
        run_times,
        volumes,
        loaded_files,
        version_label: layout.label,
    })
}

/// Parse a prefetch file. Transparently decompresses the `MAM\x04`
/// Xpress-Huffman wrapper (Windows 10/11) before parsing the inner SCCA data.
pub(crate) fn parse_prefetch(data: &[u8]) -> Result<ParsedPrefetch, PrefetchError> {
    if data.len() >= 8 && data[0..4] == MAM_SIG {
        let out_size = u32_le(data, 4)? as usize;
        // Cap before decompressing: the decoder does `Vec::with_capacity(out_size)`,
        // so an attacker-declared huge size must be refused up front.
        if out_size == 0 || out_size > crate::MAX_PREFETCH_SIZE {
            return Err(PrefetchError::CompressedSizeImplausible(out_size));
        }
        let compressed = &data[8..];
        let decompressed =
            xpress_huffman::decompress(compressed, out_size).map_err(PrefetchError::Decompress)?;
        return parse_scca(&decompressed);
    }
    parse_scca(data)
}
