//! Uncompressed TAR extractor.
//!
//! Full-file-system mobile dumps often arrive as a `.tar`. Because TAR is
//! uncompressed, each entry's bytes are a contiguous range of the archive, so a
//! child [`WindowSource`] over the parent exposes the entry with **no copy and no
//! extra memory** — the office/mobile/hashing parsers then run on the contents
//! (the orchestrator re-queues produced FileEntries).
//!
//! Gzip/bzip2/xz emit a `tar` subtype child once decompressed; this module also
//! accepts those (once they carry their decompressed bytes) and a `.tar`
//! FileEntry, gating on the `ustar` magic at offset 257.

use crate::entry_path::{resolve_entry_path, EntryPath};
use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::{DataSource, RunListDataSource, SourceCursor, WindowSource},
    io::{read_full, IncompleteReason},
    module::{ForensicsModule, InputCapability, ModuleError},
};
use serde_json::json;
use std::sync::Arc;
use tracing::{info, warn};

pub struct TarExpanderModule;

impl ForensicsModule for TarExpanderModule {
    fn id(&self) -> &str {
        "container.tar_extractor"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::Container, ArtifactType::FileEntry]
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
        let lower = name.to_lowercase();

        let Some(data_source) = artifact.data.as_ref() else {
            return Ok(Vec::new());
        };

        // Gate: a `tar` subtype (from the gz/bz2/xz expanders) or a .tar name,
        // then confirm the ustar magic so a mislabelled file is not our problem.
        let claims_tar = artifact.subtype() == Some("tar") || lower.ends_with(".tar");
        if !claims_tar {
            return Ok(Vec::new());
        }
        // `read_full` loops: a single `read_at` delivering fewer than five bytes
        // is ordinary on a windowed or decompressed-spill source, and treating
        // it as "not a tar" would drop the whole archive with only a log line.
        let mut magic = [0u8; 5];
        let read = read_full(data_source.as_ref(), 257, &mut magic);
        if read < 5 || &magic != b"ustar" {
            return Ok(Vec::new());
        }

        info!("TarExpanderModule processing: {}", name);
        let archive_len = data_source.size();
        let cursor = EofProbe::new(SourceCursor::new(data_source.clone()));
        let mut archive = tar::Archive::new(cursor);
        let entries = match archive.entries() {
            Ok(e) => e,
            Err(e) => {
                warn!("Failed to read tar {}: {}", name, e);
                // An archive we could not open at all is not an empty archive.
                return Ok(vec![archive_status(
                    artifact,
                    name,
                    0,
                    "tar_unreadable",
                    &e.to_string(),
                )]);
            }
        };

        let mut produced = Vec::new();
        // Why the walk stopped short of the end of the archive, when it did.
        // TAR is sequential: a header that will not parse leaves no way to find
        // the next one, so the walk MUST stop — but everything after that point
        // is then unknown, not absent, and the archive has to say so.
        let mut stopped: Option<(&'static str, String)> = None;
        for entry in entries {
            let mut entry = match entry {
                Ok(e) => e,
                // Truncated/corrupt: keep what parsed, and record that the rest
                // of the archive was never read (B2-159).
                Err(e) => {
                    stopped = Some(("tar_entry_unreadable", e.to_string()));
                    break;
                }
            };
            let entry_type = entry.header().entry_type();
            // A PAX `g` header carries attributes for the archive, not a
            // member: `git archive` opens every tarball with one naming the
            // commit. tar-rs consumes `x`, `L` and `K` but yields `g`, which
            // was then listed as a file no working tree ever held (HUNT-170).
            if entry_type.is_pax_global_extensions() {
                continue;
            }
            let is_dir = entry_type.is_dir();
            let is_symlink = entry_type.is_symlink();
            let is_hardlink = entry_type.is_hard_link();
            // `Entry::size`, not the header field: it is the PAX `size=` the
            // walker itself skips by. A member over 8 GiB has its ustar size
            // field zeroed by Python's `tarfile` and GNU tar's posix format,
            // so the header field listed it as an empty file (HUNT-170).
            // A POSIX-format sparse member keeps its real size and name in
            // `GNU.sparse.*` PAX keys; the header's are the packed data's.
            let pax_sparse = pax_sparse(&mut entry);
            let size = member_size(&entry, pax_sparse.as_ref());
            let path = match member_path(&entry, pax_sparse.as_ref()) {
                Ok(p) => p,
                Err(e) => {
                    // The entry exists but its name is undecodable: it is
                    // dropped from the listing, so the listing is short.
                    stopped.get_or_insert(("tar_entry_name_undecodable", e.to_string()));
                    continue;
                }
            };
            let trimmed = path.trim_end_matches('/');
            if trimmed.is_empty() {
                continue;
            }
            // Header names are the archive's, not ours: resolve them within the
            // archive so the stored path cannot claim a location outside it
            // (BUG-036), keeping the stored name where it differs.
            let EntryPath {
                full_path,
                parent_path,
                name: base,
                original,
                escapes_root,
            } = resolve_entry_path(&path);

            // A link has no bytes of its own: a symlink's are its target
            // path, and a hard link's live under the name it links to.
            let has_content = !(is_dir || is_symlink || is_hardlink);
            // The header's size is not evidence that the bytes are there: a
            // truncated archive still declares full sizes, so the content
            // source is bounded by the bytes the archive holds (BUG-274). A
            // GNU sparse member is laid out from its map (HUNT-205).
            let content = if has_content {
                member_content(data_source, &entry, size, pax_sparse.as_ref())
            } else {
                Ok(MemberContent::none())
            };

            let (entry_data, served_len, structure_unread) = match content {
                Ok(c) => {
                    let served_len = c.served_len;
                    (c.source, served_len, c.sparse.map(Ok))
                }
                Err(detail) => (None, 0, Some(Err(detail))),
            };

            let mut metadata = json!({
                "name": base,
                "path": full_path,
                "parent_path": parent_path,
                "size": size,
                "is_directory": is_dir,
                "container": "tar",
                "container_path": name,
            });
            if let Some(original) = original {
                metadata["original_name"] = json!(original);
            }
            if escapes_root {
                metadata["path_traversal"] = json!(true);
            }
            // A link is published as a link, with the target the archive
            // stored for it; listed as a file it read as an empty one
            // (HUNT-170). The target is kept exactly as stored: a symlink's is
            // relative to the link, a hard link's is another member's name.
            if is_symlink || is_hardlink {
                let target = entry
                    .link_name_bytes()
                    .map(|b| String::from_utf8_lossy(&b).into_owned());
                let (flag, key, kind) = if is_symlink {
                    ("is_symlink", "symlink_target", "symlink")
                } else {
                    ("is_hardlink", "hardlink_target", "hardlink")
                };
                metadata[flag] = json!(true);
                metadata["tar_entry_type"] = json!(kind);
                match target {
                    Some(t) => metadata[key] = json!(t),
                    None => {
                        // A link header with no target name: say so rather
                        // than let an absent key read as "not recorded".
                        metadata[key] = serde_json::Value::Null;
                        metadata["link_target_missing"] = json!(true);
                    }
                }
            }

            // What the header says about the file, which is the only record of
            // it an archive-sourced case has. A mobile full-file-system
            // extraction arrives as a tar, and without these every one of its
            // files had no time on it at all: the case's file timeline was
            // empty, and a question answered by a file's mtime — "when was this
            // device factory reset" — could not be answered from the evidence
            // that holds the answer (HUNT-094).
            //
            // tar's mtime is seconds since the Unix epoch, UTC, so it needs no
            // zone qualification. Each field is written only when the header
            // carries it.
            let header = entry.header();
            if let Ok(mtime) = header.mtime() {
                // 0 is tar's "not recorded", and dating every such file to 1970
                // would put a wall of false events on the timeline.
                if mtime > 0 {
                    if let Some(dt) = chrono::DateTime::from_timestamp(mtime as i64, 0) {
                        metadata["modified"] = json!(dt.to_rfc3339());
                    }
                }
            }
            if let Ok(mode) = header.mode() {
                metadata["mode"] = json!(format!("{:o}", mode & 0o7777));
            }
            if let Ok(uid) = header.uid() {
                metadata["uid"] = json!(uid);
            }
            if let Ok(gid) = header.gid() {
                metadata["gid"] = json!(gid);
            }
            // Android's per-app UID is what ties a file to an app, so the
            // owner names are kept where the archive carries them.
            if let Ok(Some(user)) = header.username() {
                if !user.is_empty() {
                    metadata["owner"] = json!(user);
                }
            }
            if let Ok(Some(group)) = header.groupname() {
                if !group.is_empty() {
                    metadata["group"] = json!(group);
                }
            }

            match structure_unread {
                // A GNU sparse member: its real size is `size`, of which the
                // archive stores only the mapped regions; the holes between
                // them are served as zeros at their offsets.
                Some(Ok(sparse)) => {
                    metadata["tar_sparse"] = json!(true);
                    metadata["sparse_regions"] = json!(sparse.regions);
                    metadata["sparse_stored_bytes"] = json!(sparse.stored_bytes);
                }
                // The map could not be read, so no byte can be placed: the
                // member is listed with no content, and says why.
                Some(Err(detail)) => {
                    metadata["tar_sparse"] = json!(true);
                    metadata["content_incomplete"] = json!(true);
                    metadata["content_incomplete_reason"] =
                        json!(IncompleteReason::UnresolvedStructure.as_str());
                    metadata["content_incomplete_detail"] = json!(detail);
                }
                None => {}
            }
            if has_content && metadata.get("content_incomplete").is_none() && served_len < size {
                warn!(
                    "tar {}: entry {} claims {} bytes but only {} remain in the archive",
                    name, base, size, served_len
                );
                metadata["available_size"] = json!(served_len);
                metadata["content_incomplete"] = json!(true);
                metadata["content_incomplete_reason"] = json!(IncompleteReason::ShortRead.as_str());
            }

            produced.push(
                Artifact::new(
                    artifact.case_id,
                    ArtifactType::FileEntry,
                    entry_data,
                    metadata,
                )
                .with_parent(artifact.id),
            );
        }

        // The iterator ends the same way at the all-zero end-of-archive block
        // and at plain end-of-file on a header boundary. Only the first is a
        // whole archive: the second is a copy cut short, and every member
        // after the cut is unknown, not absent — GNU tar lists such a file
        // without complaint, so nothing else will say so (HUNT-170).
        // A walk that ended on a read error already has its record; one that
        // only dropped an undecodable name did reach the end, so the missing
        // marker is the larger gap and the dropped name is kept in its detail.
        let walk_ended_cleanly = !matches!(stopped, Some(("tar_entry_unreadable", _)));
        let probe = archive.into_inner();
        let mut trailing: Option<TrailingBytes> = None;
        if walk_ended_cleanly && !probe.hit_eof() {
            // The walk ended on the end-of-archive block, which ends exactly
            // where the reader stopped. Anything after it that is not zero
            // padding — a second archive joined with `cat`, or other data —
            // is never read by a tar walker, so it is recorded (HUNT-206).
            trailing = trailing_bytes(data_source.as_ref(), probe.consumed());
            if let Some(t) = &trailing {
                let mut detail = format!(
                    "{} bytes follow the end-of-archive block (which ends at offset {}); the first \
                     non-zero byte is at offset {}. ",
                    t.len, t.offset, t.first_nonzero
                );
                match t.tar_header_at {
                    Some(at) => detail.push_str(&format!(
                        "A tar header begins at offset {at}: a second archive appears to have \
                         been appended, and its members were not listed (GNU tar lists them \
                         only with --ignore-zeros)"
                    )),
                    None => detail.push_str(
                        "They do not begin a tar header and were not read: they may be \
                         unrelated data or the remains of further members",
                    ),
                }
                if let Some((_, earlier)) = stopped.take() {
                    detail.push_str(&format!(
                        ". Separately, an entry was dropped because its name could not be \
                         decoded: {earlier}"
                    ));
                }
                stopped = Some(("tar_bytes_after_end_marker", detail));
            }
        }
        if walk_ended_cleanly && probe.hit_eof() {
            let mut detail = format!(
                "The archive ends at byte {archive_len} on a header boundary with no \
                 end-of-archive (all-zero) block: it was cut short there, and any members after \
                 that point were never seen"
            );
            if let Some((_, earlier)) = stopped.take() {
                detail.push_str(&format!(
                    ". Separately, an entry was dropped because its name could not be \
                     decoded: {earlier}"
                ));
            }
            stopped = Some(("tar_end_marker_missing", detail));
        }

        info!("Extracted {} entries from tar {}", produced.len(), name);
        if let Some((reason, detail)) = stopped {
            let entries_recovered = produced.len();
            let mut status = archive_status(artifact, name, entries_recovered, reason, &detail);
            if let (Some(t), "tar_bytes_after_end_marker") = (&trailing, reason) {
                status.metadata["trailing_bytes_after_end_marker"] = json!(t.len);
                status.metadata["trailing_bytes_offset"] = json!(t.offset);
                status.metadata["trailing_bytes_all_zero"] = json!(false);
                status.metadata["trailing_first_nonzero_offset"] = json!(t.first_nonzero);
                if let Some(at) = t.tar_header_at {
                    status.metadata["trailing_tar_header_at"] = json!(at);
                }
            }
            produced.push(status);
        }
        Ok(produced)
    }
}

/// A reader that remembers whether its last read hit end-of-file.
///
/// tar-rs reports "no more entries" both for the all-zero end-of-archive block
/// and for end-of-file where the next header should be. When the walk ends,
/// the last read tar-rs made was that header read: it returned bytes if the
/// terminator was there, and nothing if the file simply stopped.
///
/// It also counts the bytes read. tar-rs reads the archive sequentially with
/// no read-ahead and stops right after the first all-zero block, so when the
/// walk ends on the end marker the count is the offset just past it.
struct EofProbe<R> {
    inner: R,
    last_read_eof: bool,
    consumed: u64,
}

impl<R> EofProbe<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            last_read_eof: false,
            consumed: 0,
        }
    }

    fn hit_eof(&self) -> bool {
        self.last_read_eof
    }

    fn consumed(&self) -> u64 {
        self.consumed
    }
}

impl<R: std::io::Read> std::io::Read for EofProbe<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        if !buf.is_empty() {
            self.last_read_eof = n == 0;
        }
        self.consumed += n as u64;
        Ok(n)
    }
}

/// Non-zero bytes found after the end-of-archive block.
struct TrailingBytes {
    /// Where the bytes after the end-of-archive block start.
    offset: u64,
    /// How many there are, to the end of the archive.
    len: u64,
    /// The first byte that is not zero padding.
    first_nonzero: u64,
    /// Where a tar header (ustar magic at +257) begins, if the first non-zero
    /// byte starts one.
    tar_header_at: Option<u64>,
}

/// Look at the bytes from `offset` to the end of `source`. Zeros there are
/// the second end block and the record padding GNU tar writes (to 10 KiB), and
/// are not reported; the first non-zero byte means something follows the
/// archive. A short read is reported as non-zero at the point it fell short:
/// bytes that cannot be read are not known to be padding.
fn trailing_bytes(source: &dyn DataSource, offset: u64) -> Option<TrailingBytes> {
    let end = source.size();
    let mut buf = vec![0u8; 64 * 1024];
    let mut at = offset;
    while at < end {
        let want = ((end - at) as usize).min(buf.len());
        let got = read_full(source, at, &mut buf[..want]);
        let first = buf[..got]
            .iter()
            .position(|&b| b != 0)
            .map(|i| at + i as u64)
            .or((got < want).then_some(at + got as u64));
        if let Some(first_nonzero) = first {
            let mut magic = [0u8; 5];
            let tar_header_at = (read_full(source, first_nonzero + 257, &mut magic) == 5
                && &magic == b"ustar")
                .then_some(first_nonzero);
            return Some(TrailingBytes {
                offset,
                len: end - offset,
                first_nonzero,
                tar_header_at,
            });
        }
        at += want as u64;
    }
    None
}

/// Where a member's bytes are, as a source that serves them in the member's
/// own offsets.
struct MemberContent {
    source: Option<Arc<dyn DataSource>>,
    /// Bytes of the member served from offset 0 — the whole member unless the
    /// archive is cut short.
    served_len: u64,
    sparse: Option<SparseLayout>,
}

/// What a GNU sparse member's map says.
struct SparseLayout {
    /// Data regions in the map (zero-length entries excluded).
    regions: usize,
    /// Bytes the archive stores for the member: the sum of the regions.
    stored_bytes: u64,
}

impl MemberContent {
    fn none() -> Self {
        Self {
            source: None,
            served_len: 0,
            sparse: None,
        }
    }
}

/// The content source for a regular (or contiguous) member of `size` bytes,
/// or a GNU sparse member (type `S`) of real size `size`.
///
/// A contiguous member is a window over the archive. A GNU sparse member
/// stores only its data regions, packed one after another; its map (four
/// slots in the header, then 21 per extension block while the header's
/// `isextended` flag is set) gives each region's offset in the file. tar-rs
/// validates the map but does not publish it, and its `raw_file_position` for
/// such a member is where the extension blocks begin, not the data, so the map
/// is read again here from the archive and served as a run list: each region
/// at its own offset, each hole as zeros (HUNT-205). A cut archive serves the
/// file up to the first stored byte it does not hold. `Err` names why the map
/// could not be read.
fn member_content<R: std::io::Read>(
    archive: &Arc<dyn DataSource>,
    entry: &tar::Entry<'_, R>,
    size: u64,
    pax: Option<&PaxSparse>,
) -> Result<MemberContent, String> {
    let archive_len = archive.size();
    if pax.is_none() && !entry.header().entry_type().is_gnu_sparse() {
        let offset = entry.raw_file_position();
        let served_len = size.min(archive_len.saturating_sub(offset));
        let source = (served_len > 0).then(|| {
            Arc::new(WindowSource::new(archive.clone(), offset, served_len)) as Arc<dyn DataSource>
        });
        return Ok(MemberContent {
            source,
            served_len,
            sparse: None,
        });
    }
    let (map, data_start) = match pax {
        None => gnu_sparse_map(archive.as_ref(), entry)?,
        Some(p) => {
            if p.real_size.is_none() {
                return Err(
                    "the member's PAX header marks it sparse but gives no real size".into(),
                );
            }
            match &p.map {
                Err(detail) => return Err(detail.clone()),
                Ok(PaxMap::Header(map)) => (map.clone(), entry.raw_file_position()),
                Ok(PaxMap::InData) => {
                    pax_1_0_map(archive.as_ref(), entry.raw_file_position(), entry.size())?
                }
            }
        }
    };
    let map: Vec<(u64, u64)> = map.into_iter().filter(|&(_, len)| len > 0).collect();
    let mut runs: Vec<(Option<u64>, u64)> = Vec::with_capacity(map.len() * 2 + 1);
    let mut logical = 0u64;
    let mut stored_at = data_start;
    let mut stored_bytes = 0u64;
    let mut served_len: Option<u64> = None;
    for &(offset, len) in &map {
        if offset < logical {
            return Err(format!(
                "the sparse map's region at {offset} overlaps the one before it"
            ));
        }
        if offset > logical {
            runs.push((None, offset - logical));
        }
        let present = archive_len.saturating_sub(stored_at).min(len);
        if present < len && served_len.is_none() {
            served_len = Some(offset + present);
        }
        runs.push((Some(stored_at), len));
        stored_at = stored_at.saturating_add(len);
        stored_bytes = stored_bytes.saturating_add(len);
        logical = offset.saturating_add(len);
    }
    if logical < size {
        runs.push((None, size - logical));
    }
    let served_len = served_len.unwrap_or(size).min(size);
    let source = (served_len > 0).then(|| {
        Arc::new(RunListDataSource::with_logical_size(
            archive.clone(),
            runs,
            served_len,
        )) as Arc<dyn DataSource>
    });
    Ok(MemberContent {
        source,
        served_len,
        sparse: Some(SparseLayout {
            regions: map.len(),
            stored_bytes,
        }),
    })
}

/// A GNU sparse member's map as `(offset, length)` regions, and the archive
/// offset where its stored data begins (after the header and any extension
/// blocks).
fn gnu_sparse_map<R: std::io::Read>(
    archive: &dyn DataSource,
    entry: &tar::Entry<'_, R>,
) -> Result<(Vec<(u64, u64)>, u64), String> {
    let gnu = entry
        .header()
        .as_gnu()
        .ok_or("a sparse member whose header is not in the GNU format")?;
    let mut map = Vec::new();
    let mut push = |slot: &tar::GnuSparseHeader| -> Result<(), String> {
        if slot.is_empty() {
            return Ok(());
        }
        let offset = slot.offset().map_err(|e| e.to_string())?;
        let len = slot.length().map_err(|e| e.to_string())?;
        // GNU tar ends a map whose file ends in a hole with a zero-length
        // region at the real size; it holds no bytes.
        if len > 0 {
            map.push((offset, len));
        }
        Ok(())
    };
    for slot in &gnu.sparse {
        push(slot)?;
    }
    let mut next = entry.raw_header_position() + 512;
    let mut extended = gnu.is_extended();
    while extended {
        let mut ext = tar::GnuExtSparseHeader::new();
        if read_full(archive, next, ext.as_mut_bytes()) < 512 {
            return Err(format!(
                "the sparse map's extension block at offset {next} could not be read"
            ));
        }
        for slot in ext.sparse() {
            push(slot)?;
        }
        extended = ext.is_extended();
        next += 512;
    }
    Ok((map, next))
}

/// A record saying this archive was only partly enumerated.
///
/// Files an examiner cannot see in a listing are read as files the archive did
/// not contain. When the walk stopped early that conclusion is wrong, and a
/// warning in the server log never reaches the person drawing it (B2-159).
///
/// This is a short *listing*, so it carries `inventory_incomplete` as well as
/// `content_incomplete`: the entries after the stopping point were never named,
/// let alone read. Both keys are stamped because they are read for different
/// questions — "is this file's content all there was?" and "is this listing all
/// there was?" — and a truncated tar answers no to both. `content_incomplete`
/// predates this and is kept so nothing that already reads it breaks.
fn archive_status(
    artifact: &Artifact,
    name: &str,
    entries_recovered: usize,
    reason: &'static str,
    detail: &str,
) -> Artifact {
    Artifact::new(
        artifact.case_id,
        ArtifactType::ParsedRecord,
        None,
        json!({
            "type": "ArchiveScanStatus",
            "record_type": "archive_scan_status",
            "name": format!("{} (partially extracted)", name),
            "container": "tar",
            "container_path": name,
            "content_incomplete": true,
            "content_incomplete_reason": reason,
            "inventory_incomplete": true,
            "inventory_incomplete_reason": IncompleteReason::UnresolvedStructure.as_str(),
            "entries_recovered": entries_recovered,
            "content_incomplete_detail": detail,
            "inventory_incomplete_detail": detail,
            "detail": detail,
            "message": "This archive was only partly enumerated: entries missing from \
                        the listing are not evidence that the archive did not contain them",
        }),
    )
    .with_parent(artifact.id)
}

/// Re-open one tar entry's bytes from an already-decompressed tar `tar_source`,
/// matched by its archive-internal path (the stored entry `path` without its
/// leading `/`). Returns a zero-copy [`WindowSource`] over the tar, or `None` if
/// the entry is absent, a directory, or empty. Used by the API to resolve
/// inner-file content on demand after ingest.
pub fn extract_tar_entry_source(
    tar_source: Arc<dyn DataSource>,
    internal_path: &str,
) -> Option<Arc<dyn DataSource>> {
    let cursor = SourceCursor::new(tar_source.clone());
    let mut archive = tar::Archive::new(cursor);
    for entry in archive.entries().ok()? {
        let mut entry = match entry {
            Ok(e) => e,
            Err(_) => break, // truncated/corrupt: nothing more to match
        };
        let pax_sparse = pax_sparse(&mut entry);
        let path = match member_path(&entry, pax_sparse.as_ref()) {
            Ok(p) => p,
            Err(_) => continue,
        };
        // The stored path is the resolved form (BUG-036), so an entry whose
        // header name needed resolving — `../secrets.db`, stored as
        // `/secrets.db` — must still be re-openable by the path an examiner is
        // holding; the raw header name is tried first and costs nothing.
        if path.trim_end_matches('/') != internal_path
            && resolve_entry_path(&path).full_path.trim_start_matches('/') != internal_path
        {
            continue;
        }
        // `Entry::size` honours a PAX `size=`, as ingest does (HUNT-170); a
        // POSIX sparse member's real size is its `GNU.sparse` one (HUNT-205).
        let size = member_size(&entry, pax_sparse.as_ref());
        let kind = entry.header().entry_type();
        if kind.is_dir() || kind.is_symlink() || kind.is_hard_link() || size == 0 {
            return None;
        }
        // Same source as ingest: bounded by the bytes the archive holds
        // (BUG-274), and a GNU sparse member laid out from its map (HUNT-205).
        return member_content(&tar_source, &entry, size, pax_sparse.as_ref())
            .ok()
            .and_then(|c| c.source);
    }
    None
}

/// A POSIX-format (PAX) sparse member, as GNU tar writes it with
/// `--format=posix --sparse`.
struct PaxSparse {
    /// `GNU.sparse.name`: the member's real name (0.1 and 1.0; the header
    /// names a stand-in, `GNUSparseFile.<pid>/<name>`).
    name: Option<String>,
    /// `GNU.sparse.realsize` (1.0) or `GNU.sparse.size` (0.x).
    real_size: Option<u64>,
    map: Result<PaxMap, String>,
}

enum PaxMap {
    /// 0.0 (repeated `GNU.sparse.offset`/`GNU.sparse.numbytes`) or 0.1
    /// (`GNU.sparse.map`): the map is in the header; the data starts at once.
    Header(Vec<(u64, u64)>),
    /// 1.0: the map is decimal lines at the head of the member's data, padded
    /// to a 512-byte block.
    InData,
}

/// The `GNU.sparse.*` keys of a member's PAX header, if it has any.
fn pax_sparse<R: std::io::Read>(entry: &mut tar::Entry<'_, R>) -> Option<PaxSparse> {
    let extensions = entry.pax_extensions().ok()??;
    let mut any = false;
    let mut name = None;
    let mut real_size = None;
    let mut major = None;
    let mut map_text = None;
    let mut offsets = Vec::new();
    let mut lengths = Vec::new();
    for extension in extensions.flatten() {
        let (Ok(key), Ok(value)) = (extension.key(), extension.value()) else {
            continue;
        };
        let Some(field) = key.strip_prefix("GNU.sparse.") else {
            continue;
        };
        any = true;
        match field {
            "name" => name = Some(value.to_string()),
            "realsize" | "size" => real_size = value.parse::<u64>().ok(),
            "major" => major = value.parse::<u64>().ok(),
            "map" => map_text = Some(value.to_string()),
            "offset" => offsets.push(value.parse::<u64>()),
            "numbytes" => lengths.push(value.parse::<u64>()),
            _ => {}
        }
    }
    if !any {
        return None;
    }
    let map = if major == Some(1) {
        Ok(PaxMap::InData)
    } else if let Some(text) = map_text {
        let numbers: Result<Vec<u64>, _> = text.split(',').map(|n| n.trim().parse()).collect();
        match numbers {
            Ok(n) if n.len() % 2 == 0 => {
                Ok(PaxMap::Header(n.chunks(2).map(|p| (p[0], p[1])).collect()))
            }
            _ => Err(format!(
                "the sparse map `GNU.sparse.map={text}` is not offset,length pairs"
            )),
        }
    } else if !offsets.is_empty() && offsets.len() == lengths.len() {
        offsets
            .into_iter()
            .zip(lengths)
            .map(|(o, l)| Some((o.ok()?, l.ok()?)))
            .collect::<Option<Vec<_>>>()
            .map(PaxMap::Header)
            .ok_or_else(|| "a GNU.sparse.offset or numbytes value is not a number".to_string())
    } else {
        Err(
            "the member's PAX header marks it sparse but its map is missing or unpaired"
                .to_string(),
        )
    };
    Some(PaxSparse {
        name,
        real_size,
        map,
    })
}

/// The member's size: a POSIX sparse member's real size, else `Entry::size`
/// (which honours a PAX `size=`, HUNT-170).
fn member_size<R: std::io::Read>(entry: &tar::Entry<'_, R>, pax: Option<&PaxSparse>) -> u64 {
    pax.and_then(|p| p.real_size)
        .unwrap_or_else(|| entry.size())
}

/// The member's stored path: a POSIX sparse member's `GNU.sparse.name`, else
/// the header's.
fn member_path<R: std::io::Read>(
    entry: &tar::Entry<'_, R>,
    pax: Option<&PaxSparse>,
) -> std::io::Result<String> {
    match pax.and_then(|p| p.name.clone()) {
        Some(name) => Ok(name),
        None => entry.path().map(|p| p.to_string_lossy().to_string()),
    }
}

/// A sparse 1.0 map: at `data_pos`, a decimal count then that many offset and
/// length pairs, one number per line, padded to a 512-byte block, all within
/// the member's `stored` bytes. Returns the map and where the data begins.
fn pax_1_0_map(
    archive: &dyn DataSource,
    data_pos: u64,
    stored: u64,
) -> Result<(Vec<(u64, u64)>, u64), String> {
    let mut text: Vec<u8> = Vec::new();
    let mut parsed = 0usize;
    let mut count: Option<u64> = None;
    let mut numbers: Vec<u64> = Vec::new();
    loop {
        while let Some(nl) = text[parsed..].iter().position(|&b| b == b'\n') {
            let line = String::from_utf8_lossy(&text[parsed..parsed + nl]).into_owned();
            let n: u64 = line.trim().parse().map_err(|_| {
                format!("the sparse map at offset {data_pos} holds `{line}` where a number belongs")
            })?;
            parsed += nl + 1;
            match count {
                None => {
                    // Each pair takes at least four bytes of map text.
                    if n > stored / 4 {
                        return Err(format!(
                            "the sparse map at offset {data_pos} claims {n} regions in a member \
                             of {stored} stored bytes"
                        ));
                    }
                    count = Some(n);
                }
                Some(_) => numbers.push(n),
            }
            if let Some(c) = count {
                if numbers.len() as u64 == 2 * c {
                    let map_len = (parsed as u64).div_ceil(512) * 512;
                    let map = numbers.chunks(2).map(|p| (p[0], p[1])).collect();
                    return Ok((map, data_pos + map_len));
                }
            }
        }
        if text.len() as u64 >= stored {
            return Err(format!(
                "the sparse map at offset {data_pos} runs past the member's {stored} stored bytes"
            ));
        }
        let mut block = [0u8; 512];
        let at = data_pos + text.len() as u64;
        if read_full(archive, at, &mut block) < block.len() {
            return Err(format!(
                "the sparse map's block at offset {at} could not be read"
            ));
        }
        text.extend_from_slice(&block);
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod entry_metadata_tests {
    use super::*;
    use seance_core::data_source::ByteSliceDataSource;

    /// Build a one-entry ustar archive with the header fields under test.
    fn tar_with(name: &str, mtime: u64, mode: u32, uid: u64, user: &str) -> Vec<u8> {
        let mut header = tar::Header::new_ustar();
        header.set_path(name).unwrap();
        header.set_size(4);
        header.set_mtime(mtime);
        header.set_mode(mode);
        header.set_uid(uid);
        header.set_gid(uid);
        header.set_username(user).unwrap();
        header.set_groupname(user).unwrap();
        header.set_cksum();

        let mut out = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut out);
            builder.append(&header, &b"data"[..]).unwrap();
            builder.finish().unwrap();
        }
        out
    }

    fn entries(bytes: Vec<u8>) -> Vec<Artifact> {
        let artifact = Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(Arc::new(ByteSliceDataSource::new(bytes))),
            serde_json::json!({"name": "extraction.tar"}),
        );
        TarExpanderModule.process(&artifact).expect("tar parsed")
    }

    /// HUNT-094. A mobile full-file-system extraction arrives as a tar, and the
    /// header is the only record its files have of when they were written, who
    /// owned them and what they were. None of it was read: every file in such a
    /// case had no time on it, so the file timeline was empty and a question
    /// answered by an mtime could not be answered from the evidence holding the
    /// answer.
    #[test]
    fn the_header_fields_reach_the_file_entry() {
        // 2022-01-14T00:00:00Z — the day the CTF's Pixel was factory reset.
        let out = entries(tar_with(
            "data/misc/bootstat/factory_reset",
            1642118400,
            0o640,
            1000,
            "u0_a133",
        ));
        let file = out
            .iter()
            .find(|a| a.metadata["name"] == "factory_reset")
            .expect("the entry is produced");
        assert_eq!(file.metadata["modified"], "2022-01-14T00:00:00+00:00");
        assert_eq!(file.metadata["mode"], "640");
        assert_eq!(file.metadata["uid"], 1000);
        assert_eq!(file.metadata["gid"], 1000);
        // Android's per-app user is what ties a file to an app.
        assert_eq!(file.metadata["owner"], "u0_a133");
        assert_eq!(file.metadata["group"], "u0_a133");
    }

    /// tar writes 0 for "not recorded". Dating those files to 1970 would put a
    /// wall of events on the timeline that nothing in the evidence supports.
    #[test]
    fn an_unrecorded_mtime_is_absent_not_1970() {
        let out = entries(tar_with("data/x", 0, 0o644, 0, "root"));
        let file = out
            .iter()
            .find(|a| a.metadata["name"] == "x")
            .expect("the entry is produced");
        assert!(file.metadata.get("modified").is_none());
        // The other header fields are still read.
        assert_eq!(file.metadata["mode"], "644");
    }
}
