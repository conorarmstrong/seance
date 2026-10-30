//! The two chunk kinds inside a `.tracev3` that carry its content: the
//! **Catalog** (`0x600b`) and the **Chunkset** (`0x600d`).
//!
//! # Catalog
//!
//! After the 16-byte chunk preamble a catalog opens with a 24-byte header —
//! `u16` subsystem-strings offset, `u16` process-info offset, `u16` process-info
//! count, `u16` sub-chunk offset, `u16` sub-chunk count, 6 unknown bytes and the
//! `u64` continuous time of the earliest firehose entry it covers. Every offset
//! counts from the end of that header. Then:
//!
//! * the **UUID table** — 16-byte UUIDs up to the subsystem-strings offset;
//! * the **subsystem strings** — NUL-terminated, up to the process-info offset;
//! * the **process-info entries** — each a 40-byte fixed part (`u16` index,
//!   `u16` unknown, `u16` main-UUID index, `u16` shared-cache-UUID index, `u64`
//!   first process id, `u32` second process id, `u32` pid, `u32` effective uid,
//!   `u32` unknown, `u32` UUID-entry count, `u32` unknown), that many 16-byte
//!   UUID entries (`u32` size, `u32` unknown, `u16` UUID index, 6-byte load
//!   address), a `u32` subsystem count and `u32` unknown, that many 6-byte
//!   subsystem entries (`u16` id, `u16` subsystem offset, `u16` category offset,
//!   both into the subsystem strings), padded to 8 bytes;
//! * the **sub-chunk table** — per chunkset that follows: `u64` start and `u64`
//!   end continuous time, `u32` uncompressed size, `u32` compression algorithm
//!   (`0x100` is LZ4), a `u32`-counted run of `u16` process indexes and a
//!   `u32`-counted run of `u16` subsystem-string offsets, padded to 8 bytes.
//!
//! The reader publishes whether that arithmetic came out: the process entries
//! must end at exactly the sub-chunk offset, and the sub-chunk table at exactly
//! the end of the chunk.
//!
//! # Chunkset
//!
//! A chunkset's payload is a run of blocks: `bv41` (`u32` decompressed size,
//! `u32` compressed size, an LZ4 block), `bv4-` (`u32` size, raw bytes), ending
//! at `bv4$`. Decompressed, it is a run of 8-aligned entries with the same
//! 16-byte preamble as the file's own chunks: firehose (`0x6001`), oversize
//! (`0x6002`), statedump (`0x6003`) and simpledump (`0x6004`).
//!
//! The layouts were read against the corpus fixtures and agree with Mandiant's
//! `macos-UnifiedLogs` reading, used as a comparison and not as the answer.

/// Largest decompressed chunkset accepted. Apple's are ~64 KB; a size field
/// claiming more than this is damage, not a log.
pub(crate) const MAX_CHUNKSET_BYTES: usize = 16 * 1024 * 1024;
/// Process-info entries read from one catalog.
const MAX_PROCESS_ENTRIES: usize = 65_536;

pub(crate) const TAG_FIREHOSE: u32 = 0x6001;
pub(crate) const TAG_OVERSIZE: u32 = 0x6002;
pub(crate) const TAG_STATEDUMP: u32 = 0x6003;
pub(crate) const TAG_SIMPLEDUMP: u32 = 0x6004;

fn le_u16(d: &[u8], at: usize) -> Option<u16> {
    d.get(at..at.checked_add(2)?)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
}
fn le_u32(d: &[u8], at: usize) -> Option<u32> {
    d.get(at..at.checked_add(4)?)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}
fn le_u64(d: &[u8], at: usize) -> Option<u64> {
    d.get(at..at.checked_add(8)?).map(|s| {
        let mut b = [0u8; 8];
        b.copy_from_slice(s);
        u64::from_le_bytes(b)
    })
}
pub(crate) fn pad8(n: usize) -> usize {
    (8 - n % 8) % 8
}
fn c_string(d: &[u8], at: usize) -> Option<String> {
    let rest = d.get(at..)?;
    let end = rest.iter().position(|b| *b == 0)?;
    Some(String::from_utf8_lossy(&rest[..end]).into_owned())
}

/// One image a process had loaded that logs: where it sat and which UUID.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ProcessUuid {
    pub(crate) size: u32,
    pub(crate) uuid_index: u16,
    pub(crate) load_address: u64,
}

/// A subsystem/category pair a process logged under.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Subsystem {
    pub(crate) id: u16,
    pub(crate) subsystem: Option<String>,
    pub(crate) category: Option<String>,
}

/// One catalog process-info entry.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ProcessInfo {
    pub(crate) index: u16,
    pub(crate) main_uuid_index: u16,
    pub(crate) dsc_uuid_index: u16,
    pub(crate) first_proc_id: u64,
    pub(crate) second_proc_id: u32,
    pub(crate) pid: u32,
    pub(crate) euid: u32,
    pub(crate) uuids: Vec<ProcessUuid>,
    pub(crate) subsystems: Vec<Subsystem>,
}

/// One catalog sub-chunk: the chunkset that follows and what it covers.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct SubChunk {
    pub(crate) start: u64,
    pub(crate) end: u64,
    pub(crate) uncompressed_size: u32,
    pub(crate) compression_algorithm: u32,
    pub(crate) process_indexes: Vec<u16>,
    pub(crate) string_offsets: Vec<u16>,
}

/// A parsed catalog.
#[derive(Debug, Clone, Default)]
pub(crate) struct Catalog {
    /// Continuous time, not wall time; carried for the dating the wiring
    /// will do through timesync.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) earliest_firehose_time: u64,
    /// Upper-case hex, 32 digits.
    pub(crate) uuids: Vec<String>,
    pub(crate) subsystem_strings: Vec<u8>,
    pub(crate) processes: Vec<ProcessInfo>,
    pub(crate) subchunks: Vec<SubChunk>,
    /// The catalog's own arithmetic came out (see the module docs).
    pub(crate) self_consistent: bool,
    /// What did not, in words.
    pub(crate) flaw: Option<String>,
}

impl Catalog {
    /// The number of distinct non-empty subsystem/category strings.
    #[cfg(test)]
    pub(crate) fn subsystem_string_count(&self) -> usize {
        self.subsystem_strings
            .split(|b| *b == 0)
            .filter(|s| !s.is_empty())
            .count()
    }

    /// The UUID at an index of the UUID table.
    pub(crate) fn uuid(&self, index: u16) -> Option<&str> {
        self.uuids.get(index as usize).map(String::as_str)
    }

    /// The process a firehose preamble's two process ids name.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn process(&self, first: u64, second: u32) -> Option<&ProcessInfo> {
        self.processes
            .iter()
            .find(|p| p.first_proc_id == first && p.second_proc_id == second)
    }
}

/// Parse a catalog chunk's payload (the bytes after its 16-byte preamble).
/// `None` when not even the header fits.
pub(crate) fn parse_catalog(b: &[u8]) -> Option<Catalog> {
    let sso = le_u16(b, 0)? as usize;
    let pio = le_u16(b, 2)? as usize;
    let npe = le_u16(b, 4)? as usize;
    let osc = le_u16(b, 6)? as usize;
    let nsc = le_u16(b, 8)? as usize;
    let earliest = le_u64(b, 16)?;
    const BASE: usize = 24;
    let mut cat = Catalog {
        earliest_firehose_time: earliest,
        ..Default::default()
    };
    let mut flaws: Vec<String> = Vec::new();

    if !sso.is_multiple_of(16) || pio < sso {
        flaws.push(format!(
            "the header puts the subsystem strings at {sso} and the process entries at {pio}, \
             which is not a whole number of 16-byte UUIDs followed by strings"
        ));
    }
    let uuid_end = (BASE + sso).min(b.len());
    for u in b
        .get(BASE..uuid_end)
        .unwrap_or_default()
        .as_chunks::<16>()
        .0
    {
        cat.uuids
            .push(u.iter().map(|x| format!("{x:02X}")).collect());
    }
    if let Some(s) = b.get(BASE + sso..BASE + pio.max(sso)) {
        cat.subsystem_strings = s.to_vec();
    }

    let mut o = BASE + pio;
    let mut process_walk_ok = true;
    for _ in 0..npe.min(MAX_PROCESS_ENTRIES) {
        let Some(fixed) = b.get(o..o + 40) else {
            process_walk_ok = false;
            break;
        };
        let nu = le_u32(fixed, 32).unwrap_or_default() as usize;
        let mut p = ProcessInfo {
            index: le_u16(fixed, 0).unwrap_or_default(),
            main_uuid_index: le_u16(fixed, 4).unwrap_or_default(),
            dsc_uuid_index: le_u16(fixed, 6).unwrap_or_default(),
            first_proc_id: le_u64(fixed, 8).unwrap_or_default(),
            second_proc_id: le_u32(fixed, 16).unwrap_or_default(),
            pid: le_u32(fixed, 20).unwrap_or_default(),
            euid: le_u32(fixed, 24).unwrap_or_default(),
            uuids: Vec::new(),
            subsystems: Vec::new(),
        };
        o += 40;
        let Some(entries) = nu.checked_mul(16).and_then(|n| b.get(o..o.checked_add(n)?)) else {
            process_walk_ok = false;
            break;
        };
        for e in entries.as_chunks::<16>().0 {
            let mut la = [0u8; 8];
            la[..6].copy_from_slice(&e[10..16]);
            p.uuids.push(ProcessUuid {
                size: le_u32(e, 0).unwrap_or_default(),
                uuid_index: le_u16(e, 8).unwrap_or_default(),
                load_address: u64::from_le_bytes(la),
            });
        }
        o += entries.len();
        let Some(ns) = le_u32(b, o) else {
            process_walk_ok = false;
            break;
        };
        let ns = ns as usize;
        o += 8;
        let Some(subs) = ns.checked_mul(6).and_then(|n| b.get(o..o.checked_add(n)?)) else {
            process_walk_ok = false;
            break;
        };
        for s in subs.as_chunks::<6>().0 {
            let so = le_u16(s, 2).unwrap_or_default() as usize;
            let co = le_u16(s, 4).unwrap_or_default() as usize;
            p.subsystems.push(Subsystem {
                id: le_u16(s, 0).unwrap_or_default(),
                subsystem: c_string(&cat.subsystem_strings, so),
                category: c_string(&cat.subsystem_strings, co),
            });
        }
        o += subs.len() + pad8(subs.len());
        cat.processes.push(p);
    }
    if npe > MAX_PROCESS_ENTRIES {
        flaws.push(format!(
            "the catalog declares {npe} process entries and the first {MAX_PROCESS_ENTRIES} were read"
        ));
    }
    if !process_walk_ok {
        flaws.push(format!(
            "process entry {} of {npe} runs past the end of the chunk, so it and the ones \
             after it were not read",
            cat.processes.len() + 1
        ));
    } else if o != BASE + osc {
        flaws.push(format!(
            "the process entries end at byte {o} of the chunk and the header puts the \
             sub-chunk table at {}, so the two readings of the catalog disagree",
            BASE + osc
        ));
    }

    // The sub-chunk table, read from where the header says it is.
    let mut o = BASE + osc;
    let mut sub_walk_ok = true;
    for _ in 0..nsc {
        let (Some(start), Some(end), Some(us), Some(alg), Some(ni)) = (
            le_u64(b, o),
            le_u64(b, o + 8),
            le_u32(b, o + 16),
            le_u32(b, o + 20),
            le_u32(b, o + 24),
        ) else {
            sub_walk_ok = false;
            break;
        };
        o += 28;
        let ni = ni as usize;
        let Some(idx) = ni.checked_mul(2).and_then(|n| b.get(o..o.checked_add(n)?)) else {
            sub_walk_ok = false;
            break;
        };
        o += idx.len();
        let Some(nso) = le_u32(b, o) else {
            sub_walk_ok = false;
            break;
        };
        let nso = nso as usize;
        o += 4;
        let Some(offs) = nso.checked_mul(2).and_then(|n| b.get(o..o.checked_add(n)?)) else {
            sub_walk_ok = false;
            break;
        };
        o += offs.len();
        o += pad8((ni + nso) * 2);
        cat.subchunks.push(SubChunk {
            start,
            end,
            uncompressed_size: us,
            compression_algorithm: alg,
            process_indexes: idx
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_le_bytes(*c))
                .collect(),
            string_offsets: offs
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_le_bytes(*c))
                .collect(),
        });
    }
    if !sub_walk_ok {
        flaws.push(format!(
            "sub-chunk {} of {nsc} runs past the end of the chunk",
            cat.subchunks.len() + 1
        ));
    } else if o != b.len() {
        flaws.push(format!(
            "the sub-chunk table ends at byte {o} and the chunk at {}, so {} byte(s) were not \
             accounted for",
            b.len(),
            b.len().abs_diff(o)
        ));
    }

    cat.self_consistent = flaws.is_empty();
    if !flaws.is_empty() {
        cat.flaw = Some(flaws.join("; "));
    }
    Some(cat)
}

/// Decompress a chunkset chunk's payload (the bytes after its preamble).
///
/// `Err` carries the sentence saying why it could not be, with the bytes
/// decompressed so far discarded: a partial block is not a reading of one.
pub(crate) fn decompress_chunkset(b: &[u8]) -> Result<Vec<u8>, String> {
    let mut out: Vec<u8> = Vec::new();
    let mut o = 0usize;
    loop {
        let Some(magic) = b.get(o..o + 4) else {
            return Err(format!(
                "the chunkset's block run ends at byte {o} without its `bv4$` end marker"
            ));
        };
        match magic {
            b"bv4$" => return Ok(out),
            b"bv41" => {
                let (Some(dsize), Some(csize)) = (le_u32(b, o + 4), le_u32(b, o + 8)) else {
                    return Err(format!("the LZ4 block header at byte {o} is cut short"));
                };
                let (dsize, csize) = (dsize as usize, csize as usize);
                if out.len().saturating_add(dsize) > MAX_CHUNKSET_BYTES {
                    return Err(format!(
                        "the LZ4 block at byte {o} declares {dsize} decompressed bytes, past the \
                         {MAX_CHUNKSET_BYTES}-byte ceiling for one chunkset"
                    ));
                }
                let Some(src) = b.get(o + 12..(o + 12).saturating_add(csize)) else {
                    return Err(format!(
                        "the LZ4 block at byte {o} declares {csize} compressed bytes and the \
                         chunk holds fewer"
                    ));
                };
                let block = lz4_flex::block::decompress(src, dsize)
                    .map_err(|e| format!("the LZ4 block at byte {o} does not decompress ({e})"))?;
                if block.len() != dsize {
                    return Err(format!(
                        "the LZ4 block at byte {o} decompressed to {} bytes, not the {dsize} it \
                         declares",
                        block.len()
                    ));
                }
                out.extend_from_slice(&block);
                o += 12 + csize;
            }
            b"bv4-" => {
                let Some(size) = le_u32(b, o + 4) else {
                    return Err(format!("the raw block header at byte {o} is cut short"));
                };
                let size = size as usize;
                if out.len().saturating_add(size) > MAX_CHUNKSET_BYTES {
                    return Err(format!(
                        "the raw block at byte {o} declares {size} bytes, past the ceiling"
                    ));
                }
                let Some(src) = b.get(o + 8..(o + 8).saturating_add(size)) else {
                    return Err(format!("the raw block at byte {o} runs past the chunk"));
                };
                out.extend_from_slice(src);
                o += 8 + size;
            }
            other => {
                return Err(format!(
                    "the bytes at offset {o} of the chunkset ({:02x?}) are not an LZ4 block \
                     marker",
                    other
                ))
            }
        }
    }
}

/// One entry inside a decompressed chunkset: its tag and payload.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Entry<'a> {
    pub(crate) tag: u32,
    pub(crate) payload: &'a [u8],
}

fn known_tag(t: Option<u32>) -> bool {
    matches!(
        t,
        Some(TAG_FIREHOSE | TAG_OVERSIZE | TAG_STATEDUMP | TAG_SIMPLEDUMP)
    )
}

/// A decompressed chunkset's entries, as walked.
#[derive(Debug, Default)]
pub(crate) struct EntryWalk<'a> {
    pub(crate) entries: Vec<Entry<'a>>,
    /// The framing broke before the end; the entries up to there are kept.
    pub(crate) framing_broken: bool,
    /// Entries followed directly by the next one, with none of the padding
    /// to 8 bytes the format otherwise puts after each.
    pub(crate) unpadded: usize,
}

/// Walk a decompressed chunkset's entries.
///
/// Each entry is followed by padding to a multiple of 8 **of its own data
/// size**. One corpus file breaks that: on `big_sur_public_private_data_mix`'s
/// `Special/0000000000000008.tracev3`, 132 entries are followed directly by
/// the next with no padding at all. So where the padded position does not
/// hold an entry tag and the unpadded one does, the walk takes the unpadded
/// one and counts it — a stated observation, never a silent guess — and where
/// neither does, the framing is broken and the walk stops.
pub(crate) fn walk_entries(d: &[u8]) -> EntryWalk<'_> {
    let mut w = EntryWalk::default();
    let (list, broken, unpadded) = entries_inner(d);
    w.entries = list;
    w.framing_broken = broken;
    w.unpadded = unpadded;
    w
}

/// The walk itself: entries, whether the framing broke, and the unpadded
/// count.
fn entries_inner(d: &[u8]) -> (Vec<Entry<'_>>, bool, usize) {
    let mut unpadded = 0usize;
    let mut out = Vec::new();
    let mut o = 0usize;
    while o < d.len() {
        let (Some(tag), Some(_sub_tag), Some(size)) =
            (le_u32(d, o), le_u32(d, o + 4), le_u64(d, o + 8))
        else {
            // Fewer than 16 bytes left: the tail padding of the block, if all
            // zero; anything else is a cut entry.
            return (out, d[o..].iter().any(|x| *x != 0), unpadded);
        };
        let Some(payload) = usize::try_from(size)
            .ok()
            .and_then(|n| d.get(o + 16..(o + 16).checked_add(n)?))
        else {
            return (out, true, unpadded);
        };
        if tag == 0 && size == 0 {
            // Zero padding after the last entry.
            return (out, d[o..].iter().any(|x| *x != 0), unpadded);
        }
        out.push(Entry { tag, payload });
        let end = o + 16 + payload.len();
        let padded = end + pad8(payload.len());
        o = if padded < d.len() && !known_tag(le_u32(d, padded)) && known_tag(le_u32(d, end)) {
            unpadded += 1;
            end
        } else {
            padded
        };
    }
    (out, false, unpadded)
}

/// Entry counts by kind.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct EntryCounts {
    pub(crate) firehose: usize,
    pub(crate) oversize: usize,
    pub(crate) statedump: usize,
    pub(crate) simpledump: usize,
    pub(crate) other: usize,
    pub(crate) framing_broken: bool,
    /// Entries with no padding after them — see [`walk_entries`].
    pub(crate) unpadded: usize,
}

/// Count a decompressed chunkset's entries by kind.
pub(crate) fn count_entries(d: &[u8]) -> EntryCounts {
    let w = walk_entries(d);
    let mut c = EntryCounts {
        framing_broken: w.framing_broken,
        unpadded: w.unpadded,
        ..Default::default()
    };
    for e in w.entries {
        match e.tag {
            TAG_FIREHOSE => c.firehose += 1,
            TAG_OVERSIZE => c.oversize += 1,
            TAG_STATEDUMP => c.statedump += 1,
            TAG_SIMPLEDUMP => c.simpledump += 1,
            _ => c.other += 1,
        }
    }
    c
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn corpus() -> std::path::PathBuf {
        std::path::PathBuf::from(std::env::var_os("HOME").unwrap_or_default())
            .join("forensic_corpora/mandiant_unifiedlogs/test_data")
    }

    fn fixture(rel: &str) -> Option<Vec<u8>> {
        let p = corpus().join(rel);
        match std::fs::read(&p) {
            Ok(b) => Some(b),
            Err(_) => {
                eprintln!("skipping: {} is not present", p.display());
                None
            }
        }
    }

    #[test]
    fn the_big_sur_catalog_chunk_yields_its_uuids_subsystems_and_processes() {
        let Some(raw) = fixture("Catalog Tests/big_sur_catalog.raw") else {
            return;
        };
        // The fixture is the whole chunk, preamble included.
        assert_eq!(u32::from_le_bytes(raw[0..4].try_into().unwrap()), 0x600b);
        let cat = parse_catalog(&raw[16..]).expect("a catalog");
        assert!(cat.self_consistent, "{:?}", cat.flaw);
        assert_eq!(cat.uuids.len(), 53);
        assert_eq!(cat.subsystem_string_count(), 166);
        assert_eq!(cat.processes.len(), 46);
        assert_eq!(cat.subchunks.len(), 5);
        assert_eq!(cat.earliest_firehose_time, 3_007_941_183);
        let first = &cat.processes[0];
        assert_eq!((first.pid, first.euid), (58, 0));
        assert_eq!((first.first_proc_id, first.second_proc_id), (58, 429));
        assert_eq!(first.subsystems.len(), 5);
        assert_eq!(cat.subchunks[0].compression_algorithm, 0x100);
        assert_eq!(cat.subchunks[0].uncompressed_size, 64_152);
        assert_eq!(
            first.subsystems[0].subsystem.as_deref(),
            Some("com.apple.clouddocs")
        );
    }

    #[test]
    fn a_catalog_cut_short_keeps_what_it_read_and_says_so() {
        let Some(raw) = fixture("Catalog Tests/big_sur_catalog.raw") else {
            return;
        };
        let cut = &raw[16..raw.len() / 2];
        let cat = parse_catalog(cut).expect("the header still fits");
        assert!(!cat.self_consistent);
        assert!(cat.flaw.as_deref().unwrap().contains("runs past"));
        assert_eq!(cat.uuids.len(), 53, "the UUID table was whole");
        assert!(!cat.processes.is_empty() && cat.processes.len() < 46);
    }

    #[test]
    fn a_bv41_chunkset_decompresses_to_its_declared_size() {
        let Some(raw) = fixture("Chunkset Tests/high_sierra_compressed_chunkset.raw") else {
            return;
        };
        assert_eq!(u32::from_le_bytes(raw[0..4].try_into().unwrap()), 0x600d);
        let d = decompress_chunkset(&raw[16..]).expect("it decompresses");
        assert_eq!(d.len(), 0xf3b8, "the size its bv41 header declares");
        let c = count_entries(&d);
        assert!(!c.framing_broken);
        assert_eq!(c, HIGH_SIERRA_COUNTS);
    }

    #[test]
    fn a_decompressed_chunkset_counts_its_entries_by_type() {
        for (rel, want) in [
            (
                "Chunkset Tests/big_sur_statedump_chunkset.raw",
                (0, 0, 1, 0),
            ),
            ("Chunkset Tests/big_sur_oversize_chunkset.raw", (0, 1, 0, 0)),
            (
                "Chunkset Tests/monterey_chunkset_simpledump.raw",
                (0, 0, 0, 1),
            ),
            ("Chunkset Tests/big_sur_firehose_chunkset.raw", (1, 0, 0, 0)),
            ("Chunkset Tests/big_sur_chunkset.raw", BIG_SUR_CHUNKSET),
        ] {
            let Some(raw) = fixture(rel) else {
                return;
            };
            let c = count_entries(&raw);
            assert!(!c.framing_broken, "{rel}");
            assert_eq!(
                (c.firehose, c.oversize, c.statedump, c.simpledump),
                want,
                "{rel}"
            );
            assert_eq!(c.other, 0, "{rel}");
        }
    }

    #[test]
    fn a_chunkset_whose_lz4_stream_is_corrupt_is_marked_not_dropped() {
        // A bv41 header declaring 64 bytes out and 8 bytes of garbage in.
        let mut b = b"bv41".to_vec();
        b.extend_from_slice(&64u32.to_le_bytes());
        b.extend_from_slice(&8u32.to_le_bytes());
        b.extend_from_slice(&[0xff; 8]);
        b.extend_from_slice(b"bv4$");
        let e = decompress_chunkset(&b).unwrap_err();
        assert!(
            e.contains("does not decompress") || e.contains("decompressed to"),
            "{e}"
        );
        // A block run with no end marker is not a whole chunkset either.
        let mut raw = b"bv4-".to_vec();
        raw.extend_from_slice(&4u32.to_le_bytes());
        raw.extend_from_slice(b"abcd");
        assert!(decompress_chunkset(&raw)
            .unwrap_err()
            .contains("end marker"));
        raw.extend_from_slice(b"bv4$");
        assert_eq!(decompress_chunkset(&raw).unwrap(), b"abcd");
        // An absurd declared size is refused before anything is allocated.
        let mut big = b"bv41".to_vec();
        big.extend_from_slice(&u32::MAX.to_le_bytes());
        big.extend_from_slice(&0u32.to_le_bytes());
        assert!(decompress_chunkset(&big).unwrap_err().contains("ceiling"));
    }

    fn entry(tag: u32, payload: &[u8], pad: bool, out: &mut Vec<u8>) {
        out.extend_from_slice(&tag.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        out.extend_from_slice(payload);
        if pad {
            out.extend(std::iter::repeat_n(0u8, (8 - payload.len() % 8) % 8));
        }
    }

    #[test]
    fn an_entry_with_no_padding_after_it_is_followed_and_counted() {
        let mut d = Vec::new();
        entry(0x6001, &[1; 13], true, &mut d);
        entry(0x6002, &[2; 13], false, &mut d); // no padding after this one
        entry(0x6001, &[3; 8], true, &mut d);
        let c = count_entries(&d);
        assert_eq!((c.firehose, c.oversize), (2, 1));
        assert_eq!(c.unpadded, 1);
        assert!(!c.framing_broken);
        // Neither position holding an entry is broken framing, not a guess.
        let mut bad = Vec::new();
        entry(0x6001, &[1; 13], false, &mut bad);
        bad.extend_from_slice(&[0xee; 24]);
        let c = count_entries(&bad);
        assert_eq!(c.firehose, 1);
        assert!(c.framing_broken);
    }

    const HIGH_SIERRA_COUNTS: EntryCounts = EntryCounts {
        firehose: 21,
        oversize: 0,
        statedump: 0,
        simpledump: 0,
        other: 0,
        framing_broken: false,
        unpadded: 0,
    };
    const BIG_SUR_CHUNKSET: (usize, usize, usize, usize) = (26, 0, 0, 0);
}
