//! A volume's own `$MFT`, located and parsed by the module's own code.
//!
//! # Why this exists
//!
//! The VSS enumerator compares each rebuilt shadow copy's `$MFT` with the live
//! volume's (HUNT-154, option B). That comparison must see exactly what this
//! module publishes for a record — the same fixup refusal, the same `$SI`/`$FN`
//! decoding, the same `$ATTRIBUTE_LIST` merge, the same run lists — or two
//! parsers of one structure come to disagree, which is how the boot-sector
//! decoders in this crate once did. So nothing here decodes a record: the
//! `$MFT` is handed to [`MftParser::process`] as a bare `$MFT`, and only its
//! `FileEntry` metadata is kept.
//!
//! # What a bare parse means for the runs
//!
//! A bare `$MFT` has no volume behind it, so the module stamps every
//! non-resident stream `volume_not_in_evidence` and attaches no content
//! (HUNT-161). The run lists themselves are still published, as byte offsets
//! in the volume window (the cluster size is supplied here), which is what a
//! caller that *does* hold the volume — a rebuilt shadow copy — needs to serve
//! them. Re-deriving the incompleteness stamps is that caller's job.
//!
//! # The module's own volume path reads through this too
//!
//! [`MftParser::process`] on a `FileSystem` artifact reads the `$MFT` through
//! [`VolumeMft::table`] — the table's own runs — and nothing else of the
//! volume. It used to step the whole volume window a record at a time and
//! publish every slot that began `FILE`: `$MFTMirr`'s copies, and on a volume
//! with shadow copies the older records preserved in diff-area blocks, each as
//! a live file under the record number in its header (HUNT-251).

use crate::{parse_ntfs_boot_sector, MftParser};
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::{ByteSliceDataSource, DataSource, RunListDataSource, WindowSource};
use serde_json::{json, Map, Value};
use std::sync::Arc;

/// Records read from the start of the `$MFT` to find record 0's own runs.
///
/// Sixteen covers the system files; an `$ATTRIBUTE_LIST` on `$MFT` whose
/// extension records lie further in is retried through the runs already found
/// (see [`locate_volume_mft`]).
const LOCATE_RECORDS: u64 = 16;

/// `$MFTMirr` holds copies of the first four records, `$MFT` itself first.
const MIRROR_RECORDS: u64 = 4;

/// Records of the partly-located `$MFT` searched for the extension records
/// that complete record 0's own run list, when those lie past
/// [`LOCATE_RECORDS`]. Bounds the retry at 64 MiB of 1,024-byte records.
const RETRY_RECORDS: u64 = 65_536;

/// Which copy of record 0 the `$MFT`'s run list was read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Record0Source {
    /// Record 0 at the boot sector's `$MFT` cluster — the table itself.
    Mft,
    /// The `$MFT`'s record 0 did not parse (torn, or unreadable); its copy at
    /// the boot sector's `$MFTMirr` cluster did. The copy is the one Windows
    /// keeps for exactly this, but it may be older than the table.
    MftMirr,
}

impl Record0Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Record0Source::Mft => "mft_record_0",
            Record0Source::MftMirr => "mftmirr_record_0",
        }
    }
}

/// Where a volume's `$MFT` lies, from its boot sector and its record 0.
#[derive(Debug, Clone)]
pub struct VolumeMft {
    /// Bytes per cluster, from the boot sector.
    pub cluster_size: u64,
    /// Bytes per MFT record, from the boot sector.
    pub record_size: u64,
    /// The `$MFT`'s own `$DATA` byte runs within the volume window.
    pub runs: Vec<(Option<u64>, u64)>,
    /// The `$MFT`'s logical size (its `$DATA` real size).
    pub size: u64,
    /// False when record 0's run list is known to be short of the `$MFT`.
    pub runs_complete: bool,
    /// Which copy of record 0 the runs came from.
    pub record0_source: Record0Source,
}

impl VolumeMft {
    /// The `$MFT` as a stream: record `n` at byte `n * record_size`, read
    /// through the table's own runs and nothing else. Where the runs are
    /// short of [`Self::size`] the missing tail reads as zeros, which no
    /// record signature matches; [`Self::runs_complete`] says so.
    pub fn table(&self, volume: &Arc<dyn DataSource>) -> Arc<dyn DataSource> {
        Arc::new(RunListDataSource::with_logical_size(
            volume.clone(),
            self.runs.clone(),
            self.size,
        ))
    }

    /// Bytes of the `$MFT` that its located runs actually reach (holes and
    /// the unlocated tail excluded).
    pub fn located_bytes(&self) -> u64 {
        let mut logical = 0u64;
        let mut located = 0u64;
        for (start, len) in &self.runs {
            let take = (*len).min(self.size.saturating_sub(logical));
            if start.is_some() {
                located = located.saturating_add(take);
            }
            logical = logical.saturating_add(take);
            if logical >= self.size {
                break;
            }
        }
        located
    }

    /// The volume byte offset of `table_offset` in the `$MFT` stream, or
    /// `None` when it falls in a hole or past the runs.
    pub fn volume_offset(&self, table_offset: u64) -> Option<u64> {
        let mut logical = 0u64;
        for (start, len) in &self.runs {
            if table_offset < logical.saturating_add(*len) {
                return start.map(|s| s + (table_offset - logical));
            }
            logical = logical.saturating_add(*len);
        }
        None
    }
}

/// Read up to `records` whole records starting at `offset` of `volume`.
fn read_records(
    volume: &Arc<dyn DataSource>,
    offset: u64,
    record_size: u64,
    records: u64,
) -> Option<Vec<u8>> {
    let len = record_size.checked_mul(records)?;
    let mut head = vec![0u8; len as usize];
    let mut got = 0usize;
    while got < head.len() {
        match volume.read_at(offset + got as u64, &mut head[got..]) {
            Ok(0) | Err(_) => break,
            Ok(n) => got += n,
        }
    }
    // Whole records only: a torn tail would be refused by the fixup check
    // anyway, but record 0 itself must be there.
    let whole = (got as u64 / record_size) * record_size;
    if whole == 0 {
        return None;
    }
    head.truncate(whole as usize);
    Some(head)
}

/// Record 0's byte runs, the table's logical size, and whether the runs are
/// whole.
type Record0Runs = (Vec<(Option<u64>, u64)>, u64, bool);

/// Record 0's runs, logical size and completeness, parsed out of a stream
/// that begins at record 0.
fn record0_runs(
    stream: Arc<dyn DataSource>,
    cluster_size: u64,
    record_size: u64,
) -> Option<Record0Runs> {
    let records = parse_bare_mft(stream, cluster_size, record_size).ok()?;
    let record0 = records
        .into_iter()
        .find(|m| m.get("record_number").and_then(Value::as_u64) == Some(0))?;
    let runs = runs_from_metadata(record0.get("data_runs")?)?;
    let size = record0.get("size").and_then(Value::as_u64)?;
    let runs_complete = record0.get("data_runs_complete").and_then(Value::as_bool) != Some(false);
    if runs.is_empty() || size == 0 {
        return None;
    }
    Some((runs, size, runs_complete))
}

/// Locate the `$MFT` of the NTFS volume `volume` serves, or `None` when it
/// has no NTFS boot sector or neither the `$MFT`'s record 0 nor its
/// `$MFTMirr` copy parses.
///
/// When record 0 carries an `$ATTRIBUTE_LIST` whose extension records lie
/// past the first [`LOCATE_RECORDS`], the runs found so far are used to read
/// up to [`RETRY_RECORDS`] of the table and record 0 is parsed again with its
/// extension records in reach. What is still short after that is reported
/// through [`VolumeMft::runs_complete`], not guessed past.
pub fn locate_volume_mft(volume: &Arc<dyn DataSource>) -> Option<VolumeMft> {
    let boot = parse_ntfs_boot_sector(volume.as_ref())?;
    let cluster_size = boot.cluster_size();
    let record_size = boot.mft_record_size()?;
    if cluster_size == 0 || record_size == 0 {
        return None;
    }
    let at = |lcn: i64| -> Option<u64> {
        if lcn < 0 {
            return None;
        }
        (lcn as u64).checked_mul(cluster_size)
    };
    let from = |offset: Option<u64>, records: u64| {
        let head = read_records(volume, offset?, record_size, records)?;
        record0_runs(
            Arc::new(ByteSliceDataSource::new(head)),
            cluster_size,
            record_size,
        )
    };

    let (mut runs, size, mut runs_complete, record0_source) =
        match from(at(boot.mft_cluster), LOCATE_RECORDS) {
            Some((r, s, c)) => (r, s, c, Record0Source::Mft),
            None => {
                let (r, s, c) = from(at(boot.mft_mirror_cluster), MIRROR_RECORDS)?;
                (r, s, c, Record0Source::MftMirr)
            }
        };

    if !runs_complete {
        // Read record 0 again out of the part of the table its runs reach,
        // so extension records further in resolve.
        let partial: Arc<dyn DataSource> = Arc::new(RunListDataSource::from_allocation(
            volume.clone(),
            runs.clone(),
        ));
        let window = partial
            .size()
            .min(size)
            .min(RETRY_RECORDS.saturating_mul(record_size));
        let window = (window / record_size) * record_size;
        if window > record_size * LOCATE_RECORDS {
            if let Some((r, s, c)) = record0_runs(
                Arc::new(WindowSource::new(partial, 0, window)),
                cluster_size,
                record_size,
            ) {
                if s == size {
                    runs = r;
                    runs_complete = c;
                }
            }
        }
    }

    Some(VolumeMft {
        cluster_size,
        record_size,
        runs,
        size,
        runs_complete,
        record0_source,
    })
}

/// Parse a bare `$MFT` stream exactly as the module does, calling `each` with
/// the metadata of every base-record `FileEntry` it publishes (alternate data
/// stream entries dropped; their names are on the base record's `ads_names`).
///
/// The records reach `each` as the pass makes them, in batches, and are not
/// kept: a caller that wants a comparison or a count holds what it needs and
/// nothing more. Collecting the whole set first was 3.9 GB for one real
/// `$MFT` before the comparison had started (HUNT-125).
///
/// `cluster_size` turns the records' cluster runs into byte offsets in the
/// volume window the `$MFT` came from; `record_size` is the volume's record
/// size. The stream must start with a `FILE` record.
pub fn parse_bare_mft_each(
    mft: Arc<dyn DataSource>,
    cluster_size: u64,
    record_size: u64,
    each: &mut dyn FnMut(Map<String, Value>),
) -> Result<(), String> {
    let artifact = Artifact::new(
        uuid::Uuid::nil(),
        ArtifactType::RawEvidence,
        Some(mft),
        json!({
            "name": "$MFT",
            "cluster_size": cluster_size,
            "mft_record_size": record_size,
        }),
    );
    let mut deliver = |batch: Vec<Artifact>| {
        for a in batch {
            if a.artifact_type != ArtifactType::FileEntry {
                continue;
            }
            if let Value::Object(m) = a.metadata {
                if m.get("is_ads").and_then(Value::as_bool) != Some(true) {
                    each(m);
                }
            }
        }
    };
    let rest = MftParser::new()
        .process_records(
            &artifact,
            Some(&mut deliver),
            crate::EVENT_FLUSH_BATCH,
            true,
        )
        .map_err(|e| e.to_string())?;
    deliver(rest);
    Ok(())
}

/// [`parse_bare_mft_each`], collected. For a caller that wants the whole set;
/// it holds every record at once, so a large `$MFT` is better walked.
pub fn parse_bare_mft(
    mft: Arc<dyn DataSource>,
    cluster_size: u64,
    record_size: u64,
) -> Result<Vec<Map<String, Value>>, String> {
    let mut out = Vec::new();
    parse_bare_mft_each(mft, cluster_size, record_size, &mut |m| out.push(m))?;
    Ok(out)
}

/// Decode the published `[[offset|null, length], ...]` run list.
pub fn runs_from_metadata(value: &Value) -> Option<Vec<(Option<u64>, u64)>> {
    value
        .as_array()?
        .iter()
        .map(|pair| {
            let pair = pair.as_array()?;
            let offset = match pair.first()? {
                Value::Null => None,
                v => Some(v.as_u64()?),
            };
            Some((offset, pair.get(1)?.as_u64()?))
        })
        .collect()
}
