//! Apple Unified Logs — `*.tracev3` (`/var/db/diagnostics/`).
//!
//! The unified log is the central modern macOS/iOS log. A `.tracev3` file is a
//! sequence of 8-byte-aligned chunks, each with a 16-byte preamble
//! (`tag: u32, sub_tag: u32, data_size: u64`, little-endian): a Header chunk
//! (`0x1000`), then Catalog (`0x600b`) and Chunkset (`0x600d`) chunks holding the
//! firehose/oversize/statedump entries.
//!
//! # Scope, stated honestly
//!
//! This parses and inventories the **chunk structure** — proof the file is a
//! unified log, which boot/log sessions it spans, how much it holds — and
//! surfaces it as a record so unified logs are no longer invisible to Séance.
//! It also decompresses each chunkset (LZ4 `bv41` blocks) and counts the
//! entries inside by kind, and reads each catalog's UUID table, processes and
//! subsystems — see [`crate::unifiedlog_chunks`].
//!
//! When the file is read where it lies — a loose file on disk, or an entry in
//! a ZIP — it also **decodes each message** against its own tree through
//! [`crate::unifiedlog_decode`]: the `uuidtext`/`dsc` catalogue one directory
//! up (a `.logarchive`) or two up (`/var/db/diagnostics` beside
//! `/var/db/uuidtext`), and the `timesync` database that dates it. Each
//! message becomes a `unifiedlog_message` record under the file's record, up to
//! a per-file cap that the counts outlive. A file inside a disk image cannot
//! reach its tree yet, and its record says **"tree not reachable, not
//! decoded"** rather than presenting a structural summary as a decoded log.
//! Oversize arguments are joined to their tracepoints within the same file,
//! and statedump and simpledump entries become messages of their own; a
//! statedump's protocol-buffer or custom-object data is kept as bytes.

use anyhow::Result;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    io::IncompleteReason,
    module::{ForensicsModule, InputCapability, ModuleError},
};
use serde_json::json;
use tracing::info;

use crate::firehose::{self, parse_firehose};
use crate::unifiedlog_chunks::{
    count_entries, decompress_chunkset, parse_catalog, walk_entries, EntryCounts, TAG_FIREHOSE,
    TAG_OVERSIZE, TAG_SIMPLEDUMP, TAG_STATEDUMP,
};
use crate::unifiedlog_decode::{self as decode, Decoder, Message, MAX_MESSAGE_RECORDS};
use crate::unifiedlog_dumps::{parse_simpledump, parse_statedump};
use crate::{basename_lower, Staged};

const TAG_HEADER: u32 = 0x1000;
const TAG_CATALOG: u32 = 0x600b;
const TAG_CHUNKSET: u32 = 0x600d;
/// Guard against a corrupt size field spinning the walk forever.
const MAX_CHUNKS: usize = 5_000_000;
/// Largest tracev3 we read. Individual files are typically ≤ tens of MB.
const MAX_BYTES: u64 = 512 * 1024 * 1024;

pub struct UnifiedLogParser;

fn le_u32(d: &[u8], off: usize) -> Option<u32> {
    d.get(off..off + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}
fn le_u64(d: &[u8], off: usize) -> Option<u64> {
    d.get(off..off + 8)
        .map(|s| u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
}

/// Whether the name is the one the OS gives a unified log.
fn named_tracev3(name: &str) -> bool {
    basename_lower(name).ends_with(".tracev3")
}

/// Worth staging and inventorying: either the OS's own name for a unified log,
/// or the header tag. The tag alone is not enough to CLAIM one — see
/// [`corroborated`] — but it is enough to look.
fn looks_like_tracev3(name: &str, head: &[u8]) -> bool {
    named_tracev3(name) || le_u32(head, 0) == Some(TAG_HEADER)
}

/// Whether a file may be reported as a unified log.
///
/// The header tag is four bytes that spell the integer 4096, which is a common
/// opening value for any binary carrying a size or offset field — so matching on
/// it alone claimed unrelated files. On DFRWS 2021's Raspberry Pi image that
/// made `sw_bundle_init.bin`, Pi firmware, three Apple Unified Log records with
/// zero catalog and zero chunkset chunks (`HUNT-084`).
///
/// A real log carries Catalog and Chunkset chunks; a lone Header chunk is the
/// shape a coincidence takes. So a file matched **by tag alone** must show at
/// least one of them before it is claimed. A file the OS itself named
/// `.tracev3` is reported whatever its contents, because there the claim rests
/// on that name rather than on a four-byte coincidence — and a truncated or
/// empty log under its own name is a finding, not a false positive.
fn corroborated(name: &str, inv: &Inventory) -> bool {
    named_tracev3(name) || inv.catalog > 0 || inv.chunkset > 0
}

/// The chunk inventory of a tracev3 file.
#[derive(Default)]
struct Inventory {
    total: usize,
    header: usize,
    catalog: usize,
    chunkset: usize,
    other: usize,
    /// `MAX_CHUNKS` stopped the walk.
    capped: bool,
    /// The framing stopped making sense before the end of the staged bytes: a
    /// chunk declared a size that overflows, does not advance, or runs past
    /// what we hold. The chunks counted so far are real; the rest of the file
    /// was not inventoried, and a count that does not say so reads as the whole
    /// log.
    framing_broken: bool,
    /// Chunksets whose blocks decompressed, and those that did not, with the
    /// first few reasons in words.
    chunksets_decompressed: usize,
    chunksets_failed: usize,
    chunkset_failures: Vec<String>,
    /// Entry counts across every decompressed chunkset.
    entries: EntryCounts,
    /// Chunksets whose entry framing broke part-way.
    chunksets_framing_broken: usize,
    /// Catalog totals.
    catalog_uuids: usize,
    catalog_process_entries: usize,
    catalog_flaws: Vec<String>,
    /// Distinct processes the catalogs name, bounded.
    processes: Vec<CatalogProcess>,
    processes_capped: bool,
    subsystems: std::collections::BTreeSet<String>,
    tracepoints: TracepointCounts,
    /// Per-message decoding against the file's own tree, when its source can
    /// climb to it (ROADMAP §1.6).
    decoder: Option<Decoder>,
}

/// One process a catalog names: who it ran as and which binary it was.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct CatalogProcess {
    pid: u32,
    euid: u32,
    main_uuid: Option<String>,
    dsc_uuid: Option<String>,
}

/// Processes listed on one record; the count is always whole.
const MAX_LISTED_PROCESSES: usize = 512;
/// Subsystem names listed on one record.
const MAX_LISTED_SUBSYSTEMS: usize = 512;
/// Decompression failures described in words; the count is always whole.
const MAX_FAILURE_SENTENCES: usize = 4;

/// Tracepoint counts across every firehose entry.
#[derive(Default)]
struct TracepointCounts {
    log: usize,
    activity: usize,
    signpost: usize,
    trace: usize,
    loss: usize,
    other: usize,
    not_read_whole: usize,
    /// Firehose entries whose own walk stopped early.
    entries_not_read_whole: usize,
    /// Entries the log itself says it dropped, summed over loss records.
    entries_lost: u64,
    first_flaws: Vec<String>,
    /// Where format strings live, by location kind.
    locations: std::collections::BTreeMap<&'static str, usize>,
}

impl TracepointCounts {
    fn total(&self) -> usize {
        self.log + self.activity + self.signpost + self.trace + self.loss + self.other
    }
}

impl Inventory {
    /// Parse one firehose entry to its tracepoints and count them.
    fn firehose(&mut self, payload: &[u8]) {
        let tp = &mut self.tracepoints;
        let Some(chunk) = parse_firehose(payload) else {
            tp.entries_not_read_whole += 1;
            if tp.first_flaws.len() < MAX_FAILURE_SENTENCES {
                tp.first_flaws
                    .push("a firehose entry too short to hold its own preamble".into());
            }
            return;
        };
        if let Some(flaw) = &chunk.flaw {
            tp.entries_not_read_whole += 1;
            if tp.first_flaws.len() < MAX_FAILURE_SENTENCES {
                tp.first_flaws.push(flaw.clone());
            }
        }
        if let Some(d) = self.decoder.as_mut() {
            d.firehose(&chunk);
        }
        for t in &chunk.tracepoints {
            match t.activity_type {
                firehose::LOG => tp.log += 1,
                firehose::ACTIVITY => tp.activity += 1,
                firehose::SIGNPOST => tp.signpost += 1,
                firehose::TRACE => tp.trace += 1,
                firehose::LOSS => tp.loss += 1,
                _ => tp.other += 1,
            }
            *tp.locations.entry(t.location.as_str()).or_default() += 1;
            if let Some(loss) = &t.loss {
                tp.entries_lost = tp.entries_lost.saturating_add(loss.count);
            }
            if let Some(flaw) = &t.flaw {
                tp.not_read_whole += 1;
                if tp.first_flaws.len() < MAX_FAILURE_SENTENCES {
                    tp.first_flaws.push(flaw.clone());
                }
            }
        }
    }

    /// Read the content of a Catalog or Chunkset chunk into the totals.
    fn absorb(&mut self, tag: u32, payload: &[u8]) {
        match tag {
            TAG_HEADER => {
                if let Some(d) = self.decoder.as_mut() {
                    d.header(payload);
                }
            }
            TAG_CATALOG => {
                let Some(cat) = parse_catalog(payload) else {
                    self.catalog_flaws
                        .push("a catalog chunk too short to hold its own header".into());
                    return;
                };
                if let Some(flaw) = &cat.flaw {
                    self.catalog_flaws.push(flaw.clone());
                }
                if let Some(d) = self.decoder.as_mut() {
                    d.catalog(&cat);
                }
                self.catalog_uuids += cat.uuids.len();
                self.catalog_process_entries += cat.processes.len();
                for p in &cat.processes {
                    for s in &p.subsystems {
                        if let Some(name) = &s.subsystem {
                            if !name.is_empty() {
                                self.subsystems.insert(name.clone());
                            }
                        }
                    }
                    let entry = CatalogProcess {
                        pid: p.pid,
                        euid: p.euid,
                        main_uuid: cat.uuid(p.main_uuid_index).map(str::to_string),
                        dsc_uuid: cat.uuid(p.dsc_uuid_index).map(str::to_string),
                    };
                    if self.processes.contains(&entry) {
                        continue;
                    }
                    if self.processes.len() < MAX_LISTED_PROCESSES {
                        self.processes.push(entry);
                    } else {
                        self.processes_capped = true;
                    }
                }
            }
            TAG_CHUNKSET => match decompress_chunkset(payload) {
                Ok(bytes) => {
                    self.chunksets_decompressed += 1;
                    let c = count_entries(&bytes);
                    for entry in walk_entries(&bytes).entries {
                        if entry.tag == TAG_FIREHOSE {
                            self.firehose(entry.payload);
                        } else if let Some(d) = self.decoder.as_mut() {
                            match entry.tag {
                                TAG_OVERSIZE => match firehose::parse_oversize(entry.payload) {
                                    Some(o) => d.oversize(&o),
                                    None => d.summary.oversize_entries_flawed += 1,
                                },
                                TAG_STATEDUMP => match parse_statedump(entry.payload) {
                                    Some(sd) => d.statedump(&sd),
                                    None => d.summary.dumps_not_read_whole += 1,
                                },
                                TAG_SIMPLEDUMP => match parse_simpledump(entry.payload) {
                                    Some(sd) => d.simpledump(&sd),
                                    None => d.summary.dumps_not_read_whole += 1,
                                },
                                _ => {}
                            }
                        }
                    }
                    self.entries.firehose += c.firehose;
                    self.entries.oversize += c.oversize;
                    self.entries.statedump += c.statedump;
                    self.entries.simpledump += c.simpledump;
                    self.entries.other += c.other;
                    self.entries.unpadded += c.unpadded;
                    if c.framing_broken {
                        self.chunksets_framing_broken += 1;
                    }
                }
                Err(why) => {
                    self.chunksets_failed += 1;
                    if self.chunkset_failures.len() < MAX_FAILURE_SENTENCES {
                        self.chunkset_failures.push(why);
                    }
                }
            },
            _ => {}
        }
    }
}

/// Walk the chunk framing. Returns `None` only if the first chunk is not a
/// Header chunk (so this is not a tracev3), else the inventory.
///
/// Every mid-walk failure sets a flag and stops rather than answering `None`:
/// answering `None` after a valid Header chunk made one corrupt size field
/// erase the whole file from the case.
fn inventory(data: &[u8], decoder: Option<Decoder>) -> Option<Inventory> {
    if le_u32(data, 0)? != TAG_HEADER {
        return None;
    }
    let mut inv = Inventory {
        decoder,
        ..Inventory::default()
    };
    let mut off = 0usize;
    while off.checked_add(16).is_some_and(|end| end <= data.len()) {
        // Both reads sit inside the bound just checked; a `None` here would be
        // a bug in that bound rather than malformed input, and is treated as
        // framing loss rather than discarding the chunks already counted.
        let (Some(tag), Some(data_size)) = (le_u32(data, off), le_u64(data, off + 8)) else {
            inv.framing_broken = true;
            break;
        };
        match tag {
            TAG_HEADER => inv.header += 1,
            TAG_CATALOG => inv.catalog += 1,
            TAG_CHUNKSET => inv.chunkset += 1,
            _ => inv.other += 1,
        }
        inv.total += 1;
        if inv.total > MAX_CHUNKS {
            inv.capped = true;
            break;
        }
        // Advance past this chunk, then align to the next 8-byte boundary.
        let Some(end) = usize::try_from(data_size)
            .ok()
            .and_then(|size| off.checked_add(16)?.checked_add(size))
        else {
            inv.framing_broken = true;
            break;
        };
        if end > data.len() {
            // The chunk claims more payload than the file holds.
            inv.framing_broken = true;
            break;
        }
        inv.absorb(tag, &data[off + 16..end]);
        let Some(aligned) = end.checked_add(7).map(|padded| padded & !7) else {
            inv.framing_broken = true;
            break;
        };
        if aligned <= off {
            inv.framing_broken = true;
            break; // zero-progress guard against a malformed size
        }
        off = aligned;
    }
    Some(inv)
}

impl ForensicsModule for UnifiedLogParser {
    fn id(&self) -> &str {
        "macos.unifiedlog"
    }
    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }
    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::FileEntry]
    }
    fn input_capability(&self) -> InputCapability {
        InputCapability::RandomAccess
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        let name = artifact
            .metadata
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let Some(ds) = artifact.data.as_ref() else {
            return Ok(Vec::new());
        };
        // Cheap magic peek before committing to a full read.
        let mut head = [0u8; 16];
        let n = seance_core::io::read_full(ds.as_ref(), 0, &mut head);
        if !looks_like_tracev3(name, &head[..n]) {
            return Ok(Vec::new());
        }

        let staged = Staged::read(ds.as_ref(), MAX_BYTES);
        // A source that can climb to the rest of its tree gets a decoder; one
        // that cannot (a file inside a disk image) is inventoried only.
        let can_climb = ds.supports_ancestors();
        let Some(mut inv) = inventory(&staged.bytes, Decoder::new(ds.clone())) else {
            return Ok(Vec::new()); // first chunk is not a Header: not a tracev3
        };
        // The header tag alone is a four-byte coincidence away from any binary
        // that opens with the integer 4096; a log proves itself with catalog or
        // chunkset chunks (HUNT-084).
        if !corroborated(name, &inv) {
            return Ok(Vec::new());
        }

        let mut decoded = inv.decoder.take();
        if let Some(d) = decoded.as_mut() {
            d.finish();
        }
        let mut meta = serde_json::Map::new();
        meta.insert("type".into(), json!("UnifiedLog"));
        meta.insert("subtype".into(), json!("tracev3"));
        meta.insert("file_name".into(), json!(name));
        meta.insert("chunk_count".into(), json!(inv.total));
        meta.insert("header_chunks".into(), json!(inv.header));
        meta.insert("catalog_chunks".into(), json!(inv.catalog));
        meta.insert("chunkset_chunks".into(), json!(inv.chunkset));
        meta.insert("other_chunks".into(), json!(inv.other));
        meta.insert("bytes".into(), json!(staged.got));
        meta.insert(
            "chunksets_decompressed".into(),
            json!(inv.chunksets_decompressed),
        );
        meta.insert(
            "chunksets_not_decompressed".into(),
            json!(inv.chunksets_failed),
        );
        meta.insert("firehose_preambles".into(), json!(inv.entries.firehose));
        meta.insert("oversize_entries".into(), json!(inv.entries.oversize));
        meta.insert("statedump_entries".into(), json!(inv.entries.statedump));
        meta.insert("simpledump_entries".into(), json!(inv.entries.simpledump));
        meta.insert("other_entries".into(), json!(inv.entries.other));
        if inv.entries.unpadded > 0 {
            // A layout observation, not a flaw: the entries were read, and the
            // count says how many followed the one before with no padding.
            meta.insert(
                "entries_without_padding".into(),
                json!(inv.entries.unpadded),
            );
        }
        let tp = &inv.tracepoints;
        meta.insert("tracepoints".into(), json!(tp.total()));
        meta.insert(
            "tracepoints_by_kind".into(),
            json!({
                "log": tp.log,
                "activity": tp.activity,
                "signpost": tp.signpost,
                "trace": tp.trace,
                "loss": tp.loss,
                "unknown": tp.other,
            }),
        );
        meta.insert(
            "tracepoints_not_read_whole".into(),
            json!(tp.not_read_whole),
        );
        meta.insert("format_string_locations".into(), json!(tp.locations));
        meta.insert(
            "firehose_entries_not_read_whole".into(),
            json!(tp.entries_not_read_whole),
        );
        if tp.loss > 0 {
            // The log's own admission that it dropped entries: evidence of a
            // gap, reported as the log states it.
            meta.insert(
                "entries_lost_per_loss_records".into(),
                json!(tp.entries_lost),
            );
        }
        meta.insert("catalog_uuids".into(), json!(inv.catalog_uuids));
        meta.insert(
            "catalog_process_entries".into(),
            json!(inv.catalog_process_entries),
        );
        meta.insert(
            "catalogs_self_consistent".into(),
            json!(inv.catalog_flaws.is_empty()),
        );
        let processes: Vec<serde_json::Value> = inv
            .processes
            .iter()
            .map(|p| {
                json!({
                    "pid": p.pid,
                    "euid": p.euid,
                    "main_uuid": p.main_uuid,
                    "dsc_uuid": p.dsc_uuid,
                })
            })
            .collect();
        meta.insert("distinct_processes".into(), json!(processes.len()));
        meta.insert("processes".into(), json!(processes));
        if inv.processes_capped {
            meta.insert(
                "processes_list_capped_at".into(),
                json!(MAX_LISTED_PROCESSES),
            );
        }
        meta.insert("distinct_subsystems".into(), json!(inv.subsystems.len()));
        meta.insert(
            "subsystems".into(),
            json!(inv
                .subsystems
                .iter()
                .take(MAX_LISTED_SUBSYSTEMS)
                .collect::<Vec<_>>()),
        );
        // Per-message decoding, when the tree was reached. Without it this is a
        // structural inventory and says so.
        let tree = decoded.as_ref().filter(|d| d.summary.tree_reachable);
        meta.insert("messages_decoded".into(), json!(tree.is_some()));
        let note = match (&decoded, tree) {
            (_, Some(_)) => String::from(
                "Unified-log messages decoded against this file's own tree: each firehose \
                 tracepoint's format string was looked up in the uuidtext/dsc catalogue beside \
                 the file, its arguments rendered, and its continuous time dated through the \
                 timesync database; a message whose arguments sit in an oversize entry of this \
                 file is rendered from it. Statedump and simpledump entries are messages of \
                 their own; a statedump's property list is decoded, its protocol-buffer or \
                 custom-object data kept as bytes and said to be undecoded.",
            ),
            (Some(_), None) => String::from(
                "Unified-log structure inventoried; messages not decoded: the catalogue tree \
                 (uuidtext and dsc) was not found beside this file — looked for at ../<XX>/ and \
                 ../dsc/ and at ./<XX>/ and ./dsc/ (a .logarchive), and at ../../uuidtext/ and \
                 ../uuidtext/ (/var/db/diagnostics) — so no format string could be looked up.",
            ),
            (None, _) => {
                let why = if can_climb {
                    "no decoder could be built for it"
                } else {
                    "this file's source cannot reach the rest of its directory tree (it was not \
                     read from a filesystem walk of a mounted volume, so no sibling listing was \
                     attached)"
                };
                format!(
                    "Unified-log structure inventoried, chunksets decompressed and their \
                     entries counted by kind, and the catalogs' processes and subsystems read. \
                     Message text needs the format strings in the log's tree (uuidtext/dsc) and \
                     the timesync database: tree not reachable, not decoded — {why}."
                )
            }
        };
        meta.insert("note".into(), json!(note));
        let mut tree_meta = serde_json::Map::new();
        tree_meta.insert("reachable".into(), json!(tree.is_some()));
        tree_meta.insert("source_can_climb".into(), json!(decoded.is_some()));
        if let Some(d) = &decoded {
            let s = &d.summary;
            tree_meta.insert("layout".into(), json!(s.layout.map(|l| l.as_str())));
            tree_meta.insert("levels_up".into(), json!(s.levels_up));
            tree_meta.insert(
                "catalogue_files_loaded".into(),
                json!(s.catalogue_files_loaded),
            );
            tree_meta.insert(
                "catalogue_files_unparsed".into(),
                json!(s.catalogue_files_unparsed),
            );
            tree_meta.insert(
                "catalogue_uuids_not_in_tree".into(),
                json!(s.catalogue_uuids_not_in_tree),
            );
            tree_meta.insert("timesync_files".into(), json!(s.timesync_files));
            // `listing` or `probing`: a probe does not see a timesync file
            // far along its sequence (HUNT-272).
            tree_meta.insert("timesync_found_by".into(), json!(s.timesync_found_by));
            tree_meta.insert("boot_uuid".into(), json!(s.boot_uuid));
            tree_meta.insert("boot_in_timesync".into(), json!(s.boot_in_timesync));
        }
        meta.insert("catalogue_tree".into(), tree_meta.into());
        if let Some(d) = tree {
            let s = &d.summary;
            meta.insert(
                "messages".into(),
                json!({
                    "resolved": s.resolved,
                    "dynamic_format": s.dynamic,
                    "unresolved": s.unresolved,
                    "loss_records": s.loss_records,
                    "arguments_rendered_raw": s.rendered_raw,
                    "records_emitted": d.messages.len(),
                    "not_emitted_over_cap": s.messages_over_cap,
                    "record_cap": MAX_MESSAGE_RECORDS,
                    "unresolved_reasons": s.unresolved_reasons,
                    "oversize_entries": s.oversize_entries,
                    "oversize_entries_not_read_whole": s.oversize_entries_flawed,
                    "oversize_joined": s.oversize_joined,
                    "oversize_not_in_file": s.oversize_not_in_file,
                    "statedumps": s.statedumps,
                    "simpledumps": s.simpledumps,
                    "statedump_data_not_decoded": s.statedump_data_not_decoded,
                    "dumps_not_read_whole": s.dumps_not_read_whole,
                }),
            );
        }

        // Everything that makes this record less than the whole log, in the
        // order that matters most to an examiner. `messages_decoded: false` is
        // this parser's private vocabulary and nothing reads it, so the last
        // entry is what carries the non-decode into the standard pair.
        let mut reasons = Vec::new();
        if let Some(reason) = staged.incomplete_reason() {
            reasons.push((reason, staged.detail(name)));
        }
        if inv.capped {
            reasons.push((
                IncompleteReason::CapReached,
                format!(
                    "the chunk walk stopped at the {MAX_CHUNKS} chunk parser cap; the chunks \
                     beyond it were not inventoried"
                ),
            ));
        }
        if inv.framing_broken {
            reasons.push((
                IncompleteReason::UnresolvedStructure,
                format!(
                    "the chunk framing stopped making sense after {} chunk(s) — one declared a \
                     size that does not fit the file — so the rest of it was not inventoried",
                    inv.total
                ),
            ));
        }
        if inv.chunksets_failed > 0 {
            reasons.push((
                IncompleteReason::Compressed,
                format!(
                    "{} of {} chunkset(s) did not decompress, so their entries are not in the \
                     counts: {}",
                    inv.chunksets_failed,
                    inv.chunkset,
                    inv.chunkset_failures.join("; ")
                ),
            ));
        }
        if inv.chunksets_framing_broken > 0 {
            reasons.push((
                IncompleteReason::UnresolvedStructure,
                format!(
                    "the entry framing inside {} decompressed chunkset(s) broke part-way, so \
                     the entries after the break are not in the counts",
                    inv.chunksets_framing_broken
                ),
            ));
        }
        if tp.not_read_whole > 0 || tp.entries_not_read_whole > 0 {
            reasons.push((
                IncompleteReason::UnresolvedStructure,
                format!(
                    "{} tracepoint(s) and {} firehose entr(ies) were not read whole: {}",
                    tp.not_read_whole,
                    tp.entries_not_read_whole,
                    tp.first_flaws.join("; ")
                ),
            ));
        }
        if !inv.catalog_flaws.is_empty() {
            reasons.push((
                IncompleteReason::UnresolvedStructure,
                format!(
                    "{} catalog(s) did not read cleanly: {}",
                    inv.catalog_flaws.len(),
                    inv.catalog_flaws
                        .iter()
                        .take(MAX_FAILURE_SENTENCES)
                        .cloned()
                        .collect::<Vec<_>>()
                        .join("; ")
                ),
            ));
        }
        match tree {
            None => reasons.push((IncompleteReason::UnresolvedStructure, note.clone())),
            Some(d) => {
                let s = &d.summary;
                if s.unresolved > 0 {
                    reasons.push((
                        IncompleteReason::UnresolvedStructure,
                        format!(
                            "{} message(s) could not be resolved to a format string and carry \
                             no text; each says why on its own record",
                            s.unresolved
                        ),
                    ));
                }
                if s.messages_over_cap > 0 {
                    reasons.push((
                        IncompleteReason::CapReached,
                        format!(
                            "{} message(s) beyond the {MAX_MESSAGE_RECORDS} record cap were \
                             decoded and counted but not emitted as records",
                            s.messages_over_cap
                        ),
                    ));
                }
                if s.oversize_not_in_file > 0 {
                    reasons.push((
                        IncompleteReason::UnresolvedStructure,
                        format!(
                            "{} message(s) keep their arguments in an oversize entry that is not \
                             in this file, so those arguments are missing; each says so",
                            s.oversize_not_in_file
                        ),
                    ));
                }
                if s.oversize_entries_flawed > 0 {
                    reasons.push((
                        IncompleteReason::UnresolvedStructure,
                        format!(
                            "{} oversize entr(ies) were not read whole",
                            s.oversize_entries_flawed
                        ),
                    ));
                }
                if s.statedump_data_not_decoded > 0 {
                    reasons.push((
                        IncompleteReason::UnresolvedStructure,
                        format!(
                            "{} statedump(s) carry protocol-buffer or custom-object data this \
                             reader does not decode; each record keeps the bytes and says so",
                            s.statedump_data_not_decoded
                        ),
                    ));
                }
                if s.dumps_not_read_whole > 0 {
                    reasons.push((
                        IncompleteReason::UnresolvedStructure,
                        format!(
                            "{} statedump/simpledump entr(ies) were not read whole",
                            s.dumps_not_read_whole
                        ),
                    ));
                }
            }
        }
        let _ = crate::stamp_incomplete(&mut meta, "content", &reasons);

        meta.insert(
            "name".into(),
            json!(format!(
                "Unified log {name}: {} chunks ({} chunkset, {} catalog), {} firehose entries",
                inv.total, inv.chunkset, inv.catalog, inv.entries.firehose
            )),
        );

        info!(
            "UnifiedLogParser: {name} — {} chunks ({} chunkset)",
            inv.total, inv.chunkset
        );
        let file = Artifact::new(
            artifact.case_id,
            ArtifactType::ParsedRecord,
            None,
            meta.into(),
        )
        .with_parent(artifact.id)
        .with_subtype("tracev3");
        let file_id = file.id;
        let mut out = vec![file];
        if let Some(d) = tree {
            out.extend(
                d.messages
                    .iter()
                    .map(|m| message_record(artifact.case_id, file_id, name, m)),
            );
        }
        Ok(out)
    }
}

/// One decoded message as a record, under its file's record.
fn message_record(case_id: uuid::Uuid, parent: uuid::Uuid, file: &str, m: &Message) -> Artifact {
    let mut meta = serde_json::Map::new();
    meta.insert("type".into(), json!("UnifiedLogMessage"));
    meta.insert("file_name".into(), json!(file));
    meta.insert("continuous_time".into(), json!(m.continuous_time));
    if let (Some(ns), Some(src)) = (m.wall_time_ns, m.time_source) {
        let secs = ns.div_euclid(1_000_000_000);
        let frac = ns.rem_euclid(1_000_000_000) as u32;
        meta.insert("timestamp".into(), json!(secs));
        meta.insert("timestamp_ns".into(), json!(ns));
        if let Some(text) = crate::to_rfc3339_nanos(secs, frac) {
            meta.insert("timestamp_rfc3339".into(), json!(text));
        }
        meta.insert("time_source".into(), json!(src.as_str()));
    }
    let dated = m.wall_time_ns.is_some() && m.time_source.is_some();
    meta.insert("dated".into(), json!(dated));
    if m.dump_kind.is_empty() {
        meta.insert(
            "activity_type".into(),
            json!(decode::activity_type_name(m.activity_type)),
        );
    } else {
        meta.insert("activity_type".into(), json!(m.dump_kind));
        for (k, v) in &m.extra {
            meta.insert(k.clone(), v.clone());
        }
    }
    if let Some(level) = decode::log_level_name(m.activity_type, m.log_type) {
        meta.insert("level".into(), json!(level));
    }
    meta.insert("thread_id".into(), json!(m.thread_id));
    let opt =
        |meta: &mut serde_json::Map<String, serde_json::Value>, k: &str, v: &Option<String>| {
            if let Some(v) = v {
                meta.insert(k.into(), json!(v));
            }
        };
    if let Some(pid) = m.pid {
        meta.insert("pid".into(), json!(pid));
    }
    if let Some(euid) = m.euid {
        meta.insert("euid".into(), json!(euid));
    }
    opt(&mut meta, "process", &m.process_path);
    opt(&mut meta, "process_uuid", &m.process_uuid);
    opt(&mut meta, "image", &m.image_path);
    opt(&mut meta, "image_uuid", &m.image_uuid);
    opt(&mut meta, "subsystem", &m.subsystem);
    opt(&mut meta, "category", &m.category);
    opt(&mut meta, "format_string", &m.format);
    opt(&mut meta, "message", &m.text);
    if m.dynamic {
        meta.insert("dynamic_format".into(), json!(true));
    }
    if m.private_arguments > 0 {
        meta.insert("private_arguments".into(), json!(m.private_arguments));
    }
    if m.rendered_raw > 0 {
        meta.insert("arguments_rendered_raw".into(), json!(m.rendered_raw));
    }
    let mut reasons = Vec::new();
    if !dated {
        reasons.push((
            IncompleteReason::UnresolvedStructure,
            "the message could not be dated: neither its boot in the timesync database nor \
             this file's header gave a clock for its continuous time"
                .to_string(),
        ));
    }
    let is_loss = m.activity_type == firehose::LOSS;
    if is_loss {
        meta.insert("lost_entries_read".into(), json!(m.lost_entries.is_some()));
    }
    if let Some(lost) = m.lost_entries {
        meta.insert("lost_entries".into(), json!(lost));
    } else if !is_loss && m.dump_kind.is_empty() {
        meta.insert("resolved".into(), json!(m.text.is_some()));
    }
    if m.extra.get("data_decoded") == Some(&json!(false)) {
        reasons.push((
            IncompleteReason::UnresolvedStructure,
            format!(
                "the statedump's {} data is not decoded; its bytes are kept as `data_hex`",
                m.extra["data_kind"].as_str().unwrap_or("unknown")
            ),
        ));
    }
    if let Some(why) = &m.unresolved {
        meta.insert("unresolved_reason".into(), json!(why));
        reasons.push((
            IncompleteReason::UnresolvedStructure,
            format!("format string not resolved: {why}"),
        ));
    }
    if let Some(r) = m.oversize_ref {
        meta.insert("oversize_ref".into(), json!(r));
        if m.arguments_from_oversize {
            meta.insert("arguments_from_oversize".into(), json!(true));
            if let Some(file) = &m.oversize_from_file {
                meta.insert("oversize_from_file".into(), json!(file));
            }
        } else if m.format.is_some() {
            let looked = m
                .oversize_missing
                .as_deref()
                .unwrap_or("the log may have written it to another file, and none was searched");
            reasons.push((
                IncompleteReason::UnresolvedStructure,
                format!(
                    "the arguments are in oversize entry {r}, which is not in this file ({looked})"
                ),
            ));
        }
    }
    if m.missing_arguments > 0 {
        meta.insert("missing_arguments".into(), json!(m.missing_arguments));
        reasons.push((
            IncompleteReason::UnresolvedStructure,
            format!(
                "{} argument(s) the format string names are not in the entry",
                m.missing_arguments
            ),
        ));
    }
    if let Some(flaw) = &m.flaw {
        reasons.push((IncompleteReason::UnresolvedStructure, flaw.clone()));
    }
    let _ = crate::stamp_incomplete(&mut meta, "content", &reasons);
    let name = match (&m.text, m.lost_entries) {
        (Some(t), _) => t.chars().take(160).collect::<String>(),
        (None, Some(n)) => format!("{n} log entries lost"),
        (None, None) if is_loss => "log entries lost (count not read)".to_string(),
        (None, None) => "(unresolved unified-log message)".to_string(),
    };
    meta.insert("name".into(), json!(name));
    Artifact::new(case_id, ArtifactType::ParsedRecord, None, meta.into())
        .with_parent(parent)
        .with_subtype("unifiedlog_message")
}

#[cfg(test)]
mod tests {
    use super::*;
    use seance_core::data_source::ByteSliceDataSource;
    use seance_core::test_support::TruncatedSource;
    use std::sync::Arc;
    use uuid::Uuid;

    /// A message neither the timesync boot nor the file header could date
    /// says it could not be dated, rather than carrying no time silently.
    #[test]
    fn an_undated_message_says_it_could_not_be_dated() {
        let m = Message {
            continuous_time: 12345,
            text: Some("hello".into()),
            ..Message::default()
        };
        let a = message_record(Uuid::new_v4(), Uuid::new_v4(), "x.tracev3", &m);
        let meta = &a.metadata;
        assert!(meta.get("timestamp").is_none());
        assert_eq!(meta["dated"], json!(false));
        assert_eq!(meta["content_incomplete"], json!(true));
        assert!(meta["content_incomplete_detail"]
            .as_str()
            .unwrap()
            .contains("could not be dated"));
    }

    /// Emit one chunk: tag, sub_tag, and `data_size` bytes of zeroed payload,
    /// padded to the next 8-byte boundary — the real tracev3 framing.
    fn chunk(tag: u32, sub_tag: u32, data_size: usize, out: &mut Vec<u8>) {
        out.extend_from_slice(&tag.to_le_bytes());
        out.extend_from_slice(&sub_tag.to_le_bytes());
        out.extend_from_slice(&(data_size as u64).to_le_bytes());
        out.extend(std::iter::repeat_n(0u8, data_size));
        while !out.len().is_multiple_of(8) {
            out.push(0);
        }
    }

    /// Emit one chunk carrying the given payload, padded to 8 bytes.
    fn chunk_with(tag: u32, sub_tag: u32, payload: &[u8], out: &mut Vec<u8>) {
        out.extend_from_slice(&tag.to_le_bytes());
        out.extend_from_slice(&sub_tag.to_le_bytes());
        out.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        out.extend_from_slice(payload);
        while !out.len().is_multiple_of(8) {
            out.push(0);
        }
    }

    /// A chunkset payload of one uncompressed (`bv4-`) block of `n` zero bytes
    /// and the end marker: 16 + n bytes.
    fn raw_chunkset(n: usize) -> Vec<u8> {
        let mut p = b"bv4-".to_vec();
        p.extend_from_slice(&(n as u32).to_le_bytes());
        p.extend(std::iter::repeat_n(0u8, n));
        p.extend_from_slice(b"bv4$");
        p
    }

    fn build_tracev3() -> Vec<u8> {
        let mut out = Vec::new();
        chunk(TAG_HEADER, 0x11, 0xd0, &mut out); // Header
                                                 // An empty catalog: the 24-byte header, every count zero.
        chunk(TAG_CATALOG, 0x11, 0x18, &mut out);
        // A chunkset of odd size (0x21), which tests the 8-byte alignment.
        chunk_with(TAG_CHUNKSET, 0x11, &raw_chunkset(0x11), &mut out);
        chunk_with(TAG_CHUNKSET, 0x11, &raw_chunkset(0x30), &mut out); // another
        out
    }

    fn run(bytes: Vec<u8>, name: &str) -> Vec<Artifact> {
        let art = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(Arc::new(ByteSliceDataSource::new(bytes))),
            json!({ "name": name }),
        );
        UnifiedLogParser.process(&art).unwrap()
    }

    fn run_source(src: Arc<dyn seance_core::data_source::DataSource>, name: &str) -> Vec<Artifact> {
        let art = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(src),
            json!({ "name": name }),
        );
        UnifiedLogParser.process(&art).unwrap()
    }

    #[test]
    fn inventories_the_chunk_structure() {
        let out = run(build_tracev3(), "0000000000000001.tracev3");
        assert_eq!(out.len(), 1);
        let m = &out[0].metadata;
        assert_eq!(m["type"], json!("UnifiedLog"));
        assert_eq!(m["chunk_count"], json!(4));
        assert_eq!(m["header_chunks"], json!(1));
        assert_eq!(m["catalog_chunks"], json!(1));
        assert_eq!(m["chunkset_chunks"], json!(2));
        // Honest about not decoding messages.
        assert_eq!(m["messages_decoded"], json!(false));
    }

    #[test]
    fn detects_by_magic_even_without_extension() {
        let out = run(build_tracev3(), "logfile.bin");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].metadata["chunk_count"], json!(4));
    }

    /// HUNT-084. Matching on the 4-byte header tag ALONE claims any file whose
    /// first four bytes happen to be the integer 4096. On DFRWS 2021's
    /// Raspberry Pi image that made `sw_bundle_init.bin` — Pi firmware — three
    /// Apple Unified Log records, each with zero catalog and zero chunkset
    /// chunks and nothing decoded. A structure with no catalog and no chunkset
    /// is not a unified log, and saying it is puts a macOS artifact in a Linux
    /// case.
    #[test]
    fn a_file_matching_only_the_header_tag_is_not_claimed_without_corroboration() {
        // Header chunk only, no catalog, no chunkset — the shape a coincidence
        // takes. Named so nothing but the magic could claim it.
        let mut bytes = Vec::new();
        chunk(TAG_HEADER, 0x11, 0xd0, &mut bytes);
        assert!(
            run(bytes.clone(), "sw_bundle_init.bin").is_empty(),
            "a lone header chunk under a non-tracev3 name is a coincidence, not a log"
        );
        // The literal shape the Pi firmware had: the tag, then bytes that
        // inventory as "other".
        let mut firmware = 4096u32.to_le_bytes().to_vec();
        firmware.extend_from_slice(&[0u8; 60]);
        assert!(run(firmware, "sw_bundle_init.bin").is_empty());
    }

    /// The name is the other half: a file the OS itself called `.tracev3` is
    /// reported even when it is short of catalog/chunkset chunks, because there
    /// the claim rests on the name the system gave it, not on a coincidence.
    #[test]
    fn a_tracev3_named_file_with_only_a_header_is_still_reported() {
        let mut bytes = Vec::new();
        chunk(TAG_HEADER, 0x11, 0xd0, &mut bytes);
        let out = run(bytes, "0000000000000001.tracev3");
        assert_eq!(out.len(), 1, "the OS's own name for it is worth reporting");
        assert_eq!(out[0].metadata["catalog_chunks"], json!(0));
    }

    #[test]
    fn a_tracev3_named_file_that_is_not_one_is_declined() {
        // .tracev3 name but first chunk is not a Header chunk.
        let out = run(vec![0xff; 64], "fake.tracev3");
        assert!(out.is_empty());
    }

    #[test]
    fn unrelated_files_are_ignored() {
        assert!(run(b"just text".to_vec(), "notes.txt").is_empty());
    }

    /// A corrupt `data_size` used to make the whole walk answer `None`, and the
    /// process step turned that into an empty result — a genuine unified log
    /// disappeared from the case over one bad field. The chunks read before it
    /// are evidence and must survive, flagged.
    #[test]
    fn a_corrupt_chunk_size_keeps_the_chunks_already_inventoried() {
        let mut bytes = Vec::new();
        chunk(TAG_HEADER, 0x11, 0xd0, &mut bytes);
        // A preamble claiming a payload that cannot be added to the offset.
        bytes.extend_from_slice(&TAG_CATALOG.to_le_bytes());
        bytes.extend_from_slice(&0x11u32.to_le_bytes());
        bytes.extend_from_slice(&u64::MAX.to_le_bytes());

        let out = run(bytes, "0000000000000001.tracev3");
        assert_eq!(out.len(), 1, "the log must not vanish over one bad size");
        let m = &out[0].metadata;
        assert_eq!(m["chunk_count"], json!(2));
        assert_eq!(m["header_chunks"], json!(1));
        assert_eq!(m["content_incomplete"], json!(true));
        assert_eq!(
            m["content_incomplete_reason"],
            json!("unresolved_structure")
        );
        assert!(m["content_incomplete_detail"]
            .as_str()
            .unwrap()
            .contains("framing"));
    }

    /// A read that stopped short of the declared size is a partial inventory,
    /// and a chunk count from partial bytes reads as the whole log without it.
    #[test]
    fn a_tracev3_read_short_of_its_declared_size_says_so() {
        let src: Arc<dyn seance_core::data_source::DataSource> =
            Arc::new(TruncatedSource::halved(build_tracev3()));
        let out = run_source(src, "0000000000000001.tracev3");
        assert_eq!(out.len(), 1);
        let m = &out[0].metadata;
        assert_eq!(m["content_incomplete"], json!(true));
        assert_eq!(m["content_incomplete_reason"], json!("short_read"));
        assert!(m["content_incomplete_detail"]
            .as_str()
            .unwrap()
            .contains("were staged"));
    }

    fn corpus() -> std::path::PathBuf {
        std::path::PathBuf::from(std::env::var_os("HOME").unwrap_or_default())
            .join("forensic_corpora/mandiant_unifiedlogs/test_data")
    }

    /// A real Big Sur Persist file: its chunksets are decompressed and their
    /// entries counted by kind, and its catalogs name the processes that
    /// logged. The figures are what this reader finds; they were cross-checked
    /// by an independent walk of the same file, not taken from another tool.
    #[test]
    fn a_real_persist_file_reports_its_entry_counts_by_type() {
        let path = corpus().join("system_logs_big_sur.logarchive/Persist/0000000000000001.tracev3");
        let Ok(bytes) = std::fs::read(&path) else {
            eprintln!("skipping: the Mandiant unified-log corpus is not present");
            return;
        };
        let out = run(bytes, "0000000000000001.tracev3");
        let m = &out[0].metadata;
        assert_eq!(m["chunksets_not_decompressed"], json!(0));
        assert_eq!(m["chunksets_decompressed"], m["chunkset_chunks"]);
        assert_eq!(m["catalogs_self_consistent"], json!(true));
        assert_eq!(m["firehose_preambles"], json!(PERSIST_1_FIREHOSE));
        assert_eq!(m["oversize_entries"], json!(PERSIST_1_OVERSIZE));
        assert_eq!(m["statedump_entries"], json!(PERSIST_1_STATEDUMP));
        assert_eq!(m["simpledump_entries"], json!(PERSIST_1_SIMPLEDUMP));
        assert_eq!(m["other_entries"], json!(0));
        assert_eq!(m["catalog_process_entries"], json!(PERSIST_1_PROCESSES));
        assert!(m["processes"].as_array().is_some_and(|p| !p.is_empty()));
        // Every firehose entry is parsed to its tracepoints, counted by kind;
        // the kinds sum to the total and none failed to read.
        let kinds = ["log", "activity", "signpost", "trace", "loss"]
            .iter()
            .map(|k| m["tracepoints_by_kind"][k].as_u64().unwrap_or_default())
            .sum::<u64>();
        assert_eq!(m["tracepoints"], json!(kinds));
        assert_eq!(m["tracepoints"], json!(PERSIST_1_TRACEPOINTS));
        assert_eq!(m["tracepoints_not_read_whole"], json!(0));
        // Where each tracepoint's format string lives, counted; every
        // tracepoint is in exactly one bucket.
        let located: u64 = m["format_string_locations"]
            .as_object()
            .expect("a location census")
            .values()
            .map(|v| v.as_u64().unwrap_or_default())
            .sum();
        assert_eq!(m["tracepoints"], json!(located));
        assert!(
            m["format_string_locations"]["shared_cache"]
                .as_u64()
                .unwrap_or_default()
                > 0
        );
        // Still not a decoded log, and it still says so.
        assert_eq!(m["messages_decoded"], json!(false));
        assert_eq!(m["content_incomplete"], json!(true));
    }

    /// ROADMAP §1.6: a Persist file read where it lies in its `.logarchive`
    /// reaches its tree one directory up and is decoded into one record per
    /// message. The counts equal Mandiant's reading of the same file — a
    /// comparison with another reading, not ground truth.
    #[test]
    fn a_logarchive_file_is_decoded_into_message_records() {
        let path = corpus().join("system_logs_big_sur.logarchive/Persist/0000000000000004.tracev3");
        if !path.is_file() {
            eprintln!("skipping: the Mandiant unified-log corpus is not present");
            return;
        }
        let src = Arc::new(seance_core::data_source::FileDataSource::new(path).unwrap());
        let out = run_source(src, "0000000000000004.tracev3");
        let file = &out[0].metadata;
        assert_eq!(file["messages_decoded"], json!(true));
        assert_eq!(file["catalogue_tree"]["reachable"], json!(true));
        assert_eq!(file["catalogue_tree"]["layout"], json!("logarchive"));
        assert_eq!(file["catalogue_tree"]["boot_in_timesync"], json!(true));
        assert_eq!(
            file["catalogue_tree"]["timesync_found_by"],
            json!("listing")
        );
        assert_eq!(file["messages"]["resolved"], json!(110_836));
        assert_eq!(file["messages"]["dynamic_format"], json!(108));
        assert_eq!(file["messages"]["unresolved"], json!(8));
        assert_eq!(file["messages"]["loss_records"], json!(1));
        assert_eq!(file["messages"]["records_emitted"], json!(110_953));
        let msgs: Vec<&Artifact> = out
            .iter()
            .filter(|a| a.metadata["subtype"] == json!("unifiedlog_message"))
            .collect();
        assert_eq!(msgs.len(), 110_953);
        assert!(msgs.iter().all(|a| a.parent_id == Some(out[0].id)));
        let first = msgs
            .iter()
            .find(|a| a.metadata["message"].is_string())
            .expect("a rendered message");
        let f = &first.metadata;
        assert_eq!(
            f["message"],
            json!("opendirectoryd (build 796.100) launched...")
        );
        assert_eq!(
            f["format_string"],
            json!("opendirectoryd (build %{public}s) launched...")
        );
        assert_eq!(f["pid"], json!(105));
        assert_eq!(f["process"], json!("/usr/libexec/opendirectoryd"));
        assert_eq!(f["subsystem"], json!("com.apple.opendirectoryd"));
        assert_eq!(f["time_source"], json!("timesync"));
        assert_eq!(
            f["timestamp_rfc3339"],
            json!("2022-01-16T03:32:13.964503310+00:00")
        );
        assert!(f.get("content_incomplete").is_none());
        // The eight the tree cannot answer say why, on the record.
        let unresolved: Vec<_> = msgs
            .iter()
            .filter(|a| a.metadata["resolved"] == json!(false))
            .collect();
        assert_eq!(unresolved.len(), 8);
        assert!(unresolved.iter().all(|a| {
            a.metadata["content_incomplete"] == json!(true)
                && a.metadata["unresolved_reason"]
                    .as_str()
                    .is_some_and(|r| r.contains("0x422304"))
        }));
    }

    /// Oversize entries reach the case: across the Big Sur archive each
    /// message whose arguments sit in an oversize entry of its own file is
    /// rendered from it and says so, and one whose entry is elsewhere says
    /// that instead of showing an empty argument.
    #[test]
    fn oversize_arguments_reach_the_message_records() {
        let root = corpus().join("system_logs_big_sur.logarchive");
        if !root.is_dir() {
            eprintln!("skipping: the Mandiant unified-log corpus is not present");
            return;
        }
        let mut stack = vec![root];
        let (mut joined, mut absent, mut from, mut said) = (0u64, 0u64, 0u64, 0u64);
        while let Some(dir) = stack.pop() {
            for e in std::fs::read_dir(&dir).unwrap().flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                    continue;
                }
                if p.extension().is_none_or(|x| x != "tracev3") {
                    continue;
                }
                let name = p.file_name().unwrap().to_string_lossy().into_owned();
                let ds =
                    Arc::new(seance_core::data_source::FileDataSource::new(p.clone()).unwrap());
                let out = run_source(ds, &name);
                let m = &out[0].metadata;
                joined += m["messages"]["oversize_joined"]
                    .as_u64()
                    .unwrap_or(u64::MAX);
                absent += m["messages"]["oversize_not_in_file"]
                    .as_u64()
                    .unwrap_or(u64::MAX);
                for r in &out[1..] {
                    if r.metadata["arguments_from_oversize"] == json!(true) {
                        from += 1;
                    }
                    if r.metadata["content_incomplete_detail"]
                        .as_str()
                        .is_some_and(|d| {
                            d.contains("oversize entry") && d.contains("not in this file")
                        })
                    {
                        said += 1;
                    }
                }
            }
        }
        assert_eq!((joined, absent), (1_259, 23));
        // The 23 whose entry is in another file of the tree are joined from it (HUNT-271, graded
        // by `an_oversize_entry_in_another_file_of_the_tree_is_joined`), so every one of the
        // 1,282 renders from an oversize entry and none says the entry is "not in this file".
        assert_eq!((from, said), (joined + absent, 0));
    }

    /// A loss record whose count was never read says so; it is not named
    /// or counted as "0 log entries lost".
    #[test]
    fn a_loss_record_without_its_count_does_not_state_a_zero() {
        let m = Message {
            activity_type: firehose::LOSS,
            lost_entries: None,
            flaw: Some("the loss record ends before its count".into()),
            ..Message::default()
        };
        let r = message_record(Uuid::new_v4(), Uuid::new_v4(), "x.tracev3", &m);
        assert!(r.metadata.get("lost_entries").is_none(), "{:?}", r.metadata);
        assert_eq!(r.metadata["lost_entries_read"], json!(false));
        assert!(r.metadata.get("resolved").is_none());
        let name = r.metadata["name"].as_str().unwrap();
        assert!(!name.contains('0'), "{name}");
        assert!(name.contains("count not read"), "{name}");
        assert_eq!(r.metadata["content_incomplete"], json!(true));
    }

    /// A message joined to an oversize entry in another file names the file;
    /// one found nowhere carries the decoder's account of where it looked.
    #[test]
    fn an_oversize_join_names_its_file_and_a_miss_says_where_it_looked() {
        let joined = Message {
            format: Some("%s".into()),
            text: Some("x".into()),
            oversize_ref: Some(3),
            arguments_from_oversize: true,
            oversize_from_file: Some("Persist/0000000000000002.tracev3".into()),
            ..Message::default()
        };
        let r = message_record(Uuid::new_v4(), Uuid::new_v4(), "a.tracev3", &joined);
        assert_eq!(
            r.metadata["oversize_from_file"],
            json!("Persist/0000000000000002.tracev3")
        );
        let missed = Message {
            format: Some("%s".into()),
            text: Some("".into()),
            oversize_ref: Some(3),
            oversize_missing: Some("WHERE IT LOOKED".into()),
            ..Message::default()
        };
        let r = message_record(Uuid::new_v4(), Uuid::new_v4(), "a.tracev3", &missed);
        let d = r.metadata["content_incomplete_detail"].as_str().unwrap();
        assert!(d.contains("WHERE IT LOOKED"), "{d}");
        assert!(r.metadata.get("oversize_from_file").is_none());
    }

    /// A loose `.tracev3` whose tree is not beside it can climb but finds
    /// nothing: the record says the catalogue was not found, and no message
    /// record is emitted with empty text.
    #[test]
    fn a_loose_file_without_its_tree_emits_no_messages_and_says_why() {
        let src = corpus().join("system_logs_big_sur.logarchive/Persist/0000000000000004.tracev3");
        if !src.is_file() {
            eprintln!("skipping: the Mandiant unified-log corpus is not present");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("x/Persist")).unwrap();
        let lone = tmp.path().join("x/Persist/0000000000000004.tracev3");
        std::fs::copy(&src, &lone).unwrap();
        let ds = Arc::new(seance_core::data_source::FileDataSource::new(lone).unwrap());
        let out = run_source(ds, "0000000000000004.tracev3");
        assert_eq!(out.len(), 1, "no message records without the tree");
        let m = &out[0].metadata;
        assert_eq!(m["messages_decoded"], json!(false));
        assert_eq!(m["catalogue_tree"]["source_can_climb"], json!(true));
        assert_eq!(m["catalogue_tree"]["reachable"], json!(false));
        assert!(m["catalogue_tree"]["catalogue_uuids_not_in_tree"]
            .as_u64()
            .is_some_and(|n| n > 0));
        assert!(m.get("messages").is_none());
        assert!(m["content_incomplete_detail"]
            .as_str()
            .unwrap()
            .contains("catalogue tree (uuidtext and dsc) was not found beside this file"));
    }

    /// A log inside a disk image (here, bytes with no path) cannot reach its
    /// tree: the record says "not reachable, not decoded" and emits no
    /// message text.
    #[test]
    fn a_log_whose_tree_cannot_be_reached_says_so() {
        let out = run(build_tracev3(), "0000000000000001.tracev3");
        assert_eq!(out.len(), 1);
        let m = &out[0].metadata;
        assert_eq!(m["messages_decoded"], json!(false));
        assert_eq!(m["catalogue_tree"]["reachable"], json!(false));
        assert!(m["content_incomplete_detail"]
            .as_str()
            .unwrap()
            .contains("tree not reachable, not decoded"));
    }

    /// A `.tracev3` listed out of a disk image is handed its tree by
    /// `attach_sibling_bundles` (ROADMAP 1.6): it can climb, so it is no longer
    /// reported as unreachable "from inside a container or disk image".
    #[test]
    fn a_log_listed_from_a_disk_image_can_climb_to_its_tree() {
        use seance_core::artifact::ArtifactType;
        let file = |path: &str, bytes: Vec<u8>| {
            Artifact::new(
                Uuid::new_v4(),
                ArtifactType::FileEntry,
                Some(Arc::new(ByteSliceDataSource::new(bytes))
                    as Arc<dyn seance_core::data_source::DataSource>),
                json!({ "name": path.rsplit('/').next().unwrap(), "path": path }),
            )
        };
        let mut listing = vec![
            file(
                "/var/db/diagnostics/Persist/0000000000000001.tracev3",
                build_tracev3(),
            ),
            file("/var/db/uuidtext/AB/CDEF0123456789", b"uuidtext".to_vec()),
            file(
                "/var/db/diagnostics/timesync/0000000000000001.timesync",
                b"ts".to_vec(),
            ),
        ];
        seance_core::data_source::attach_sibling_bundles(&mut listing);
        let out = run_source(listing[0].data.clone().unwrap(), "0000000000000001.tracev3");
        assert_eq!(out.len(), 1);
        let m = &out[0].metadata;
        assert_eq!(m["catalogue_tree"]["source_can_climb"], json!(true));
        let note = m["note"].as_str().unwrap();
        assert!(!note.contains("container or disk image"), "{note}");
        assert!(!note.contains("ROADMAP 1.6"), "{note}");
    }

    /// A chunkset whose LZ4 stream does not decompress is counted and named,
    /// not silently dropped from the entry totals.
    #[test]
    fn a_chunkset_that_will_not_decompress_is_counted_and_said() {
        let mut out = Vec::new();
        chunk(TAG_HEADER, 0x11, 0xd0, &mut out);
        // A bv41 block whose compressed bytes are garbage.
        let mut payload = b"bv41".to_vec();
        payload.extend_from_slice(&64u32.to_le_bytes());
        payload.extend_from_slice(&8u32.to_le_bytes());
        payload.extend_from_slice(&[0xff; 8]);
        payload.extend_from_slice(b"bv4$");
        out.extend_from_slice(&TAG_CHUNKSET.to_le_bytes());
        out.extend_from_slice(&0x11u32.to_le_bytes());
        out.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        out.extend_from_slice(&payload);
        while !out.len().is_multiple_of(8) {
            out.push(0);
        }
        let got = run(out, "0000000000000001.tracev3");
        let m = &got[0].metadata;
        assert_eq!(m["chunksets_not_decompressed"], json!(1));
        assert_eq!(m["chunksets_decompressed"], json!(0));
        assert!(m["content_incomplete_detail"]
            .as_str()
            .unwrap()
            .contains("did not decompress"));
    }

    /// Every deliberately damaged `.tracev3` in the corpus is either declined
    /// or reported as incomplete, and none of them panics.
    #[test]
    fn every_bad_data_tracev3_is_refused_or_marked_without_panicking() {
        let dir = corpus().join("Bad Data/TraceV3");
        let Ok(entries) = std::fs::read_dir(&dir) else {
            eprintln!("skipping: the Mandiant unified-log corpus is not present");
            return;
        };
        for e in entries.flatten() {
            let bytes = std::fs::read(e.path()).unwrap();
            let name = e.file_name().to_string_lossy().to_string();
            for rec in run(bytes, &name) {
                assert_eq!(rec.metadata["content_incomplete"], json!(true), "{name}");
            }
        }
    }

    /// Every chunkset in every `.tracev3` of the six corpus archives — High
    /// Sierra to Tahoe — decompresses, and every catalog's arithmetic comes
    /// out. This is the breadth check for the chunk reader; it pins no count.
    #[test]
    fn every_corpus_archives_chunksets_decompress_and_catalogs_tile() {
        let Ok(archives) = std::fs::read_dir(corpus()) else {
            eprintln!("skipping: the Mandiant unified-log corpus is not present");
            return;
        };
        let mut files = 0;
        for a in archives.flatten() {
            if !a.file_name().to_string_lossy().ends_with(".logarchive") {
                continue;
            }
            let mut stack = vec![a.path()];
            while let Some(dir) = stack.pop() {
                for e in std::fs::read_dir(&dir).unwrap().flatten() {
                    let p = e.path();
                    if p.is_dir() {
                        stack.push(p);
                    } else if p.extension().is_some_and(|x| x == "tracev3") {
                        let bytes = std::fs::read(&p).unwrap();
                        let inv = inventory(&bytes, None).expect("a header chunk");
                        assert!(!inv.framing_broken, "{p:?}");
                        assert_eq!(
                            inv.chunksets_failed,
                            0,
                            "{p:?}: {:?}",
                            inv.chunkset_failures.first()
                        );
                        assert_eq!(inv.chunksets_framing_broken, 0, "{p:?}");
                        assert!(
                            inv.catalog_flaws.is_empty(),
                            "{p:?}: {:?}",
                            inv.catalog_flaws
                        );
                        files += 1;
                    }
                }
            }
        }
        assert_eq!(
            files,
            7 + 16 + 19 + 16 + 34 + 33,
            "the tracev3 count PROVENANCE.md lists"
        );
    }

    /// MACOS-UNIFIEDLOG-1: the module itself, run over every `.tracev3` of
    /// the six archives where it lies, as the product would read a collected
    /// `.logarchive`. What it emits into a case — the file records' `messages`
    /// blocks and the message records — must add up to the library census
    /// (`unifiedlog_resolve`'s `CORPUS_RESOLUTION`, whose unresolved counts
    /// equal Mandiant's categories: a comparison, not ground truth), every
    /// file must reach its tree, and every message must be dated.
    #[test]
    fn every_corpus_archive_is_decoded_into_the_case() {
        use crate::unifiedlog_resolve::tests::CORPUS_RESOLUTION;
        let Ok(archives) = std::fs::read_dir(corpus()) else {
            eprintln!("skipping: the Mandiant unified-log corpus is not present");
            return;
        };
        let mut got = std::collections::BTreeMap::new();
        let mut dating = std::collections::BTreeMap::new();
        let mut entries: std::collections::BTreeMap<String, usize> = Default::default();
        for a in archives.flatten() {
            let name = a.file_name().to_string_lossy().into_owned();
            if !name.ends_with(".logarchive") {
                continue;
            }
            let mut census = (0usize, 0usize, 0usize, 0usize);
            // (files, files whose boot is in timesync, messages dated by
            // timesync, by the header, undated)
            let mut d = (0usize, 0usize, 0usize, 0usize, 0usize);
            let mut stack = vec![a.path()];
            while let Some(dir) = stack.pop() {
                for e in std::fs::read_dir(&dir).unwrap().flatten() {
                    let p = e.path();
                    if p.is_dir() {
                        stack.push(p);
                        continue;
                    }
                    if p.extension().is_none_or(|x| x != "tracev3") {
                        continue;
                    }
                    let file_name = p.file_name().unwrap().to_string_lossy().into_owned();
                    let src =
                        Arc::new(seance_core::data_source::FileDataSource::new(p.clone()).unwrap());
                    let out = run_source(src, &file_name);
                    let m = &out[0].metadata;
                    assert_eq!(m["messages_decoded"], json!(true), "{p:?}");
                    assert_eq!(m["catalogue_tree"]["layout"], json!("logarchive"), "{p:?}");
                    assert_eq!(
                        m["catalogue_tree"]["catalogue_files_unparsed"],
                        json!(0),
                        "{p:?}"
                    );
                    let n = |k: &str| m["messages"][k].as_u64().unwrap_or(u64::MAX >> 8) as usize;
                    census.0 += n("resolved");
                    census.1 += n("dynamic_format");
                    census.2 += n("unresolved");
                    census.3 += n("loss_records");
                    *entries.entry(name.clone()).or_default() += n("resolved")
                        + n("dynamic_format")
                        + n("unresolved")
                        + n("loss_records")
                        + n("statedumps")
                        + n("simpledumps");
                    assert_eq!(
                        n("records_emitted") + n("not_emitted_over_cap"),
                        n("resolved")
                            + n("dynamic_format")
                            + n("unresolved")
                            + n("loss_records")
                            + n("statedumps")
                            + n("simpledumps"),
                        "{p:?}"
                    );
                    assert_eq!(out.len() - 1, n("records_emitted"), "{p:?}");
                    d.0 += 1;
                    if m["catalogue_tree"]["boot_in_timesync"] == json!(true) {
                        d.1 += 1;
                    }
                    for r in &out[1..] {
                        match r.metadata["time_source"].as_str() {
                            Some("timesync") => d.2 += 1,
                            Some("tracev3_header") => d.3 += 1,
                            _ => d.4 += 1,
                        }
                        if r.metadata["resolved"] == json!(true) {
                            assert!(r.metadata["message"].is_string(), "{p:?}");
                        }
                    }
                }
            }
            got.insert(name.clone(), census);
            dating.insert(name, d);
        }
        let want: std::collections::BTreeMap<String, _> = CORPUS_RESOLUTION
            .iter()
            .map(|(k, v)| (k.to_string(), *v))
            .collect();
        assert_eq!(got, want);
        let want_dating: std::collections::BTreeMap<String, _> = CORPUS_DATING
            .iter()
            .map(|(k, v)| (k.to_string(), *v))
            .collect();
        assert_eq!(dating, want_dating);
        // Tracepoints plus statedumps and simpledumps, per archive, against
        // the totals Mandiant's tests pin — a comparison, not ground truth.
        for (archive, total) in MANDIANT_ENTRY_TOTALS {
            assert_eq!(entries[archive], total, "{archive}");
        }
    }

    /// Per-archive log-entry totals as Mandiant's `macos-UnifiedLogs` tests
    /// pin them (Big Sur's tracepoint share is the figure those tests quote
    /// from Apple's `log raw-dump`).
    const MANDIANT_ENTRY_TOTALS: [(&str, usize); 3] = [
        ("system_logs_high_sierra.logarchive", 569_796),
        ("system_logs_big_sur.logarchive", 747_616),
        ("system_logs_monterey.logarchive", 2_397_109),
    ];

    /// This reader's own dating of the six archives, pinned as read:
    /// (files, files whose boot is in the archive's timesync, messages dated
    /// through timesync, through the file's header, undated).
    type Dating = (usize, usize, usize, usize, usize);
    const CORPUS_DATING: [(&str, Dating); 6] = [
        ("system_logs_high_sierra.logarchive", (7, 7, 448_877, 0, 0)),
        ("system_logs_big_sur.logarchive", (16, 16, 690_250, 0, 0)),
        (
            "system_logs_big_sur_private_enabled.logarchive",
            (19, 19, 760_746, 0, 0),
        ),
        (
            "system_logs_big_sur_public_private_data_mix.logarchive",
            (16, 16, 908_733, 0, 0),
        ),
        ("system_logs_monterey.logarchive", (34, 34, 1_514_824, 0, 0)),
        ("system_logs_tahoe.logarchive", (33, 33, 2_494_919, 0, 0)),
    ];

    const PERSIST_1_FIREHOSE: usize = 220;
    const PERSIST_1_TRACEPOINTS: usize = 7_927;
    const PERSIST_1_OVERSIZE: usize = 0;
    const PERSIST_1_STATEDUMP: usize = 0;
    const PERSIST_1_SIMPLEDUMP: usize = 0;
    const PERSIST_1_PROCESSES: usize = 124;

    /// The structural inventory is never a decoded log, so the record says so
    /// through the pair every incompleteness surface reads, not only through
    /// this parser's own `messages_decoded` key.
    #[test]
    fn an_undecoded_message_log_carries_the_standard_incompleteness_pair() {
        let out = run(build_tracev3(), "0000000000000001.tracev3");
        let m = &out[0].metadata;
        assert_eq!(m["messages_decoded"], json!(false));
        assert_eq!(m["content_incomplete"], json!(true));
        assert_eq!(
            m["content_incomplete_reason"],
            json!("unresolved_structure")
        );
        assert!(m["content_incomplete_detail"]
            .as_str()
            .unwrap()
            .contains("not decoded"));
    }
}
