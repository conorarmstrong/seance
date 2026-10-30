use super::*;
use seance_core::data_source::DataSource;
use std::sync::Arc;
use uuid::Uuid;

use seance_core::data_source::ByteSliceDataSource;

/// Build an uncompressed TAR from (path, body) file entries.
fn build_tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut b = tar::Builder::new(Vec::new());
    for (name, body) in entries {
        let mut h = tar::Header::new_gnu();
        h.set_size(body.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, name, *body).unwrap();
    }
    b.into_inner().unwrap()
}

fn container(name: &str, subtype: Option<&str>, bytes: Vec<u8>) -> Artifact {
    let mut meta = json!({ "name": name });
    if let Some(s) = subtype {
        meta["subtype"] = json!(s);
    }
    let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
    Artifact::new(Uuid::new_v4(), ArtifactType::Container, Some(src), meta)
}

#[test]
fn extracts_entries_with_window_sources() {
    let body: &[u8] = b"SQLite format 3\0a viber database body";
    let other: &[u8] = b"just some text";
    let tar = build_tar(&[
        ("data/data/com.viber.voip/databases/viber_messages", body),
        ("readme.txt", other),
    ]);
    let art = container("backup.tar", Some("tar"), tar);

    let out = TarExpanderModule.process(&art).unwrap();
    let child = out
        .iter()
        .find(|a| a.metadata.get("name").and_then(|v| v.as_str()) == Some("viber_messages"))
        .expect("viber_messages entry extracted");
    assert_eq!(child.metadata["container"], "tar");

    // The window source exposes exactly the entry's bytes, no copy.
    let ds = child
        .data
        .as_ref()
        .expect("entry carries a window data source");
    assert_eq!(ds.size(), body.len() as u64);
    let mut buf = vec![0u8; body.len()];
    let n = ds.read_at(0, &mut buf).unwrap();
    assert_eq!(&buf[..n], body, "window must return the entry bytes");

    // A second entry is independent and correct too.
    let readme = out
        .iter()
        .find(|a| a.metadata.get("name").and_then(|v| v.as_str()) == Some("readme.txt"))
        .expect("readme.txt entry");
    let rds = readme.data.as_ref().unwrap();
    let mut rbuf = vec![0u8; other.len()];
    let rn = rds.read_at(0, &mut rbuf).unwrap();
    assert_eq!(&rbuf[..rn], other);
}

#[test]
fn accepts_dot_tar_name_without_subtype() {
    let tar = build_tar(&[("f.bin", b"xy")]);
    let art = container("dump.tar", None, tar);
    assert_eq!(TarExpanderModule.process(&art).unwrap().len(), 1);
}

#[test]
fn ignores_non_tar_and_missing_magic() {
    // Not claimed as tar.
    let tar = build_tar(&[("f.bin", b"xy")]);
    let art = container("notes.txt", None, tar);
    assert!(TarExpanderModule.process(&art).unwrap().is_empty());
    // Claims .tar but no ustar magic.
    let art2 = container("fake.tar", Some("tar"), b"not a tar at all".to_vec());
    assert!(TarExpanderModule.process(&art2).unwrap().is_empty());
}

#[test]
fn truncated_entry_is_flagged_and_windowed_to_the_bytes_present() {
    // BUG-274: a tar cut short mid-entry still declares the full header size.
    // The entry must not present a window that claims bytes the archive does
    // not hold, and the shortfall must be visible to the examiner.
    let body: &[u8] = &[0xEE; 4096];
    let mut tar = build_tar(&[("payload.bin", body)]);
    // Chop the last 3 KiB of the payload (and the trailing blocks with it).
    tar.truncate(tar.len() - 3072 - 1024);

    let art = container("cut.tar", Some("tar"), tar.clone());
    let out = TarExpanderModule.process(&art).unwrap();
    let child = out
        .iter()
        .find(|a| a.metadata.get("name").and_then(|v| v.as_str()) == Some("payload.bin"))
        .expect("entry extracted");

    // The logical size stays what the header recorded...
    assert_eq!(child.metadata["size"], json!(4096));
    // ...but the shortfall is declared, not silently zero-filled later.
    assert_eq!(child.metadata["content_incomplete"], json!(true));
    assert_eq!(
        child.metadata["content_incomplete_reason"],
        json!("short_read")
    );
    let available = child.metadata["available_size"].as_u64().unwrap();
    assert!(available < 4096, "available bytes: {available}");

    let ds = child.data.as_ref().expect("window data source");
    assert_eq!(
        ds.size(),
        available,
        "the window must report only the bytes the archive contains"
    );
}

#[test]
fn complete_entry_carries_no_incompleteness() {
    let body: &[u8] = b"a whole file";
    let tar = build_tar(&[("whole.txt", body)]);
    let art = container("whole.tar", Some("tar"), tar);
    let out = TarExpanderModule.process(&art).unwrap();
    let child = &out[0];
    assert!(child.metadata.get("content_incomplete").is_none());
    assert!(child.metadata.get("available_size").is_none());
    assert_eq!(child.data.as_ref().unwrap().size(), body.len() as u64);
}

/// B2-159: a bad header ends the walk — TAR is sequential, so there is no way
/// to find the next header once one will not parse. What must NOT happen is
/// the remaining entries vanishing silently: an examiner reading the listing
/// concludes the archive did not contain them.
#[test]
fn a_walk_stopped_by_a_corrupt_header_publishes_an_incomplete_archive_record() {
    let tar = build_tar(&[("first.bin", b"aaaa"), ("second.bin", b"bbbb")]);
    let mut corrupt = tar.clone();
    // The second entry's header starts one 512-byte block after the first
    // entry's header + its (one-block) payload. Wreck its checksum field.
    let second_header = 1024usize;
    for b in corrupt[second_header + 148..second_header + 156].iter_mut() {
        *b = 0x41;
    }

    let art = container("cut.tar", Some("tar"), corrupt);
    let out = TarExpanderModule.process(&art).unwrap();

    assert!(
        out.iter()
            .any(|a| a.metadata.get("name").and_then(|v| v.as_str()) == Some("first.bin")),
        "entries read before the corruption are kept"
    );
    let status = out
        .iter()
        .find(|a| {
            a.metadata.get("record_type").and_then(|v| v.as_str()) == Some("archive_scan_status")
        })
        .expect("a partly-enumerated archive must publish a status record");
    assert_eq!(status.metadata["content_incomplete"], json!(true));
    assert_eq!(
        status.metadata["content_incomplete_reason"],
        json!("tar_entry_unreadable")
    );
    // A tar that stopped mid-walk is a short LISTING, not just short content:
    // the entries after the stopping point were never named. Consumers that ask
    // "was this inventory complete?" read `inventory_incomplete`, so a record
    // that only stamped `content_incomplete` left the listing looking whole.
    assert_eq!(status.metadata["inventory_incomplete"], json!(true));
    assert_eq!(
        status.metadata["inventory_incomplete_reason"],
        json!("unresolved_structure")
    );

    // A clean archive publishes no such record, so the record keeps its meaning.
    let clean = container("ok.tar", Some("tar"), tar);
    let out = TarExpanderModule.process(&clean).unwrap();
    assert!(out.iter().all(|a| a.metadata.get("record_type").is_none()));
}

/// Build an uncompressed TAR whose entry names are written straight into the
/// header. `Builder::append_data` refuses to store `..` or an absolute name,
/// and a hostile archive is not produced by a well-behaved writer.
fn build_tar_with_raw_names(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut b = tar::Builder::new(Vec::new());
    for (name, body) in entries {
        let mut h = tar::Header::new_gnu();
        h.set_size(body.len() as u64);
        h.set_mode(0o644);
        let raw = h.as_old_mut();
        raw.name[..name.len()].copy_from_slice(name.as_bytes());
        h.set_cksum();
        b.append(&h, *body).unwrap();
    }
    b.into_inner().unwrap()
}

#[test]
fn entry_path_metadata_does_not_escape_the_archive_root() {
    // BUG-036: header names are the archive's, not ours. The path an examiner
    // reads must say where the entry lives inside the archive, while the name
    // the archive stored survives as evidence of the traversal attempt.
    let tar = build_tar_with_raw_names(&[
        ("../escape.txt", b"a"),
        ("a/../../deep_escape.txt", b"b"),
        ("/etc/passwd", b"c"),
        ("docs/notes.txt", b"d"),
    ]);
    let art = container("hostile.tar", Some("tar"), tar);
    let out = TarExpanderModule.process(&art).unwrap();

    let paths: Vec<&str> = out
        .iter()
        .filter(|a| a.artifact_type == ArtifactType::FileEntry)
        .filter_map(|a| a.metadata.get("path").and_then(|v| v.as_str()))
        .collect();
    assert_eq!(paths.len(), 4, "every entry must still be listed");
    assert!(
        paths
            .iter()
            .all(|p| !p.split('/').any(|seg| seg == "..") && !p.starts_with("//")),
        "no stored path may keep a traversal or a doubled root: {paths:?}"
    );

    let escape = out
        .iter()
        .find(|a| a.metadata.get("name").and_then(|v| v.as_str()) == Some("escape.txt"))
        .expect("the escaping entry must still be listed");
    assert_eq!(escape.metadata["path"], json!("/escape.txt"));
    assert_eq!(escape.metadata["parent_path"], json!("/"));
    assert_eq!(escape.metadata["original_name"], json!("../escape.txt"));
    assert_eq!(escape.metadata["path_traversal"], json!(true));

    // `..` inside the name is applied, then clamped at the root.
    let deep = out
        .iter()
        .find(|a| a.metadata.get("name").and_then(|v| v.as_str()) == Some("deep_escape.txt"))
        .expect("the deeply escaping entry must still be listed");
    assert_eq!(deep.metadata["path"], json!("/deep_escape.txt"));
    assert_eq!(
        deep.metadata["original_name"],
        json!("a/../../deep_escape.txt")
    );
    assert_eq!(deep.metadata["path_traversal"], json!(true));

    // An absolute stored name reaches outside an extraction root too, and used
    // to produce a doubled-slash path.
    let passwd = out
        .iter()
        .find(|a| a.metadata.get("name").and_then(|v| v.as_str()) == Some("passwd"))
        .expect("the absolutely-named entry must still be listed");
    assert_eq!(passwd.metadata["path"], json!("/etc/passwd"));
    assert_eq!(passwd.metadata["parent_path"], json!("/etc"));
    assert_eq!(passwd.metadata["original_name"], json!("/etc/passwd"));
    assert_eq!(passwd.metadata["path_traversal"], json!(true));

    // An ordinary entry is untouched: nothing was rewritten, so nothing is
    // recorded as rewritten.
    let notes = out
        .iter()
        .find(|a| a.metadata.get("name").and_then(|v| v.as_str()) == Some("notes.txt"))
        .expect("the ordinary entry must be listed");
    assert_eq!(notes.metadata["path"], json!("/docs/notes.txt"));
    assert_eq!(notes.metadata["parent_path"], json!("/docs"));
    assert!(notes.metadata.get("original_name").is_none());
    assert!(notes.metadata.get("path_traversal").is_none());
}

#[test]
fn a_resolved_entry_is_still_reopenable_by_its_stored_path() {
    // Content resolution asks for the entry by the path the examiner is holding
    // — the resolved one. An entry whose header name needed resolving must not
    // become unreadable because of it.
    let body: &[u8] = b"SQLite format 3\0escaped payload";
    let tar = build_tar_with_raw_names(&[("../secrets.db", body)]);
    let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(tar));

    let reopened = extract_tar_entry_source(src.clone(), "secrets.db")
        .expect("the stored path must re-open the entry");
    let mut buf = vec![0u8; body.len()];
    let n = reopened.read_at(0, &mut buf).unwrap();
    assert_eq!(&buf[..n], body);

    // The raw header name keeps working for anything already holding it.
    assert!(extract_tar_entry_source(src, "../secrets.db").is_some());
}

// ---------------------------------------------------------------------------
// HUNT-170: the four tar-walk silences. Every fixture below is a real
// producer's output, committed under `tests/fixtures/`.
// ---------------------------------------------------------------------------

fn status_records(out: &[Artifact]) -> Vec<&Artifact> {
    out.iter()
        .filter(|a| {
            a.metadata.get("record_type").and_then(|v| v.as_str()) == Some("archive_scan_status")
        })
        .collect()
}

fn entry_named<'a>(out: &'a [Artifact], name: &str) -> &'a Artifact {
    out.iter()
        .find(|a| a.metadata.get("name").and_then(|v| v.as_str()) == Some(name))
        .unwrap_or_else(|| panic!("{name} must be listed"))
}

/// Python's `tarfile` in PAX format, asked to describe a 9 GiB member, writes
/// the size into a PAX `x` record and **zeroes** the ustar size field (the
/// octal field tops out at 8 GiB). GNU tar in `--format=posix` does the same.
/// The walker skipped by the PAX size (tar-rs honours it) while the published
/// entry took the zeroed header field: a 9 GiB file listed as an empty one,
/// with no bytes and no flag. The fixture is those real headers followed by
/// the first 1,024 bytes of the member, as a cut-short copy would carry.
#[test]
fn a_pax_size_override_is_the_size_published() {
    let data = include_bytes!("../../tests/fixtures/pax_size_over_8gib_truncated.tar").to_vec();
    let out = TarExpanderModule
        .process(&container("huge.tar", Some("tar"), data.clone()))
        .unwrap();
    let huge = entry_named(&out, "huge.img");
    assert_eq!(huge.metadata["size"], json!(9_663_676_416u64));
    assert_eq!(huge.metadata["available_size"], json!(1024));
    assert_eq!(huge.metadata["content_incomplete"], json!(true));
    assert_eq!(
        huge.metadata["content_incomplete_reason"],
        json!("short_read")
    );
    let ds = huge
        .data
        .as_ref()
        .expect("the bytes that are present are served");
    assert_eq!(ds.size(), 1024);
    let mut head = [0u8; 22];
    ds.read_at(0, &mut head).unwrap();
    assert_eq!(&head, b"HEAD-OF-A-9-GIB-MEMBER");

    // The re-open path must agree with ingest about the same entry.
    let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));
    let reopened =
        extract_tar_entry_source(src, "data/huge.img").expect("the present bytes re-open");
    assert_eq!(reopened.size(), 1024);
}

/// GNU tar output cut on a header boundary (`head -c 1024` of a two-member
/// archive: the first member's header and data, then nothing). tar-rs returns
/// "no more entries" for EOF exactly as it does for the all-zero end-of-archive
/// block, so the walk read as complete — and GNU tar itself lists it without
/// complaint. Only one of the two members was ever seen.
#[test]
fn an_archive_with_no_end_of_archive_marker_is_recorded_as_cut_short() {
    let data = include_bytes!("../../tests/fixtures/truncated_on_header_boundary.tar").to_vec();
    let out = TarExpanderModule
        .process(&container("cut.tar", Some("tar"), data))
        .unwrap();
    entry_named(&out, "a.txt");
    let status = status_records(&out);
    assert_eq!(status.len(), 1, "{out:?}");
    let m = &status[0].metadata;
    assert_eq!(
        m["content_incomplete_reason"],
        json!("tar_end_marker_missing")
    );
    assert_eq!(m["inventory_incomplete"], json!(true));
    assert_eq!(m["entries_recovered"], json!(1));
    assert!(m["detail"].as_str().unwrap().contains("1024"), "{m}");
}

/// The counterpart: a complete archive from the same producer ends on its
/// zero blocks and carries no record, so the record means something.
#[test]
fn a_terminated_archive_carries_no_end_marker_record() {
    let data = include_bytes!("../../tests/fixtures/links.tar").to_vec();
    let out = TarExpanderModule
        .process(&container("links.tar", Some("tar"), data))
        .unwrap();
    assert!(status_records(&out).is_empty(), "{out:?}");
}

/// `git archive --format=tar` opens every tarball with a PAX `g` header named
/// `pax_global_header`, carrying the commit id. tar-rs does not consume `g`,
/// so it was published as a 52-byte file that is in no working tree.
#[test]
fn a_pax_global_header_is_not_published_as_a_file() {
    let data = include_bytes!("../../tests/fixtures/git_archive_pax_global.tar").to_vec();
    let out = TarExpanderModule
        .process(&container("src.tar", Some("tar"), data))
        .unwrap();
    let names: Vec<&str> = out
        .iter()
        .filter_map(|a| a.metadata.get("name").and_then(|v| v.as_str()))
        .collect();
    assert_eq!(names, vec!["readme.txt"], "{out:?}");
    assert!(status_records(&out).is_empty());
}

/// GNU tar of a directory holding a file, a symlink to it and a hard link to
/// it. Both links were published as ordinary files with no target: the
/// symlink as an empty file, and the hard link as an empty file although its
/// content is the 12 bytes stored under the name it links to.
#[test]
fn links_are_published_as_links_with_their_targets() {
    let data = include_bytes!("../../tests/fixtures/links.tar").to_vec();
    let out = TarExpanderModule
        .process(&container("links.tar", Some("tar"), data))
        .unwrap();

    let soft = entry_named(&out, "soft.conf");
    assert_eq!(soft.metadata["is_symlink"], json!(true));
    assert_eq!(soft.metadata["symlink_target"], json!("real.conf"));
    assert_eq!(soft.metadata["tar_entry_type"], json!("symlink"));
    assert!(soft.data.is_none());

    // GNU tar stored `hard.conf` first (sorted), so `real.conf` is the link.
    let hard = entry_named(&out, "real.conf");
    assert_eq!(hard.metadata["is_hardlink"], json!(true));
    assert_eq!(hard.metadata["hardlink_target"], json!("etc/hard.conf"));
    assert_eq!(hard.metadata["tar_entry_type"], json!("hardlink"));
    assert!(hard.data.is_none());

    let file = entry_named(&out, "hard.conf");
    assert!(file.metadata.get("is_symlink").is_none());
    assert!(file.metadata.get("is_hardlink").is_none());
    assert_eq!(file.metadata["size"], json!(12));
}

// ── GNU sparse members (HUNT-205) ───────────────────────────────────────────

fn read_member(source: &dyn DataSource, offset: u64, len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    let n = seance_core::io::read_full(source, offset, &mut buf);
    buf.truncate(n);
    buf
}

/// GNU tar 1.35, `--format=gnu --sparse`, of a 1 MiB file holding six 4 KiB
/// regions of `A`..`F` at 0, 64 KiB, 128 KiB, 256 KiB, 384 KiB and 508 KiB,
/// holes elsewhere, followed by an ordinary member. Six regions overflow the
/// four map slots of the header, so the map continues in one extension block
/// and the stored data starts at 1,024, not 512. The member was windowed as
/// its packed data from where tar-rs says its data starts (the extension
/// block) and sized to its real size, so every byte after the first hole sat
/// at the wrong offset and the extension block was served as file content.
#[test]
fn a_gnu_sparse_member_serves_its_regions_at_their_offsets_and_its_holes_as_zeros() {
    let data = include_bytes!("../../tests/fixtures/gnu_sparse.tar").to_vec();
    let out = TarExpanderModule
        .process(&container("sparse.tar", Some("tar"), data))
        .unwrap();
    let member = entry_named(&out, "disk.img");
    assert_eq!(member.metadata["size"], json!(1_048_576));
    assert!(
        member.metadata.get("content_incomplete").is_none(),
        "every stored byte is present: {}",
        member.metadata
    );
    let source = member.data.as_ref().expect("the sparse member has content");
    assert_eq!(source.size(), 1_048_576);
    let regions = [0u64, 65_536, 131_072, 262_144, 393_216, 520_192];
    for (i, &at) in regions.iter().enumerate() {
        let bytes = read_member(source.as_ref(), at, 4096);
        assert!(
            bytes.len() == 4096 && bytes.iter().all(|&b| b == 0x41 + i as u8),
            "region {i} at {at} must read as {:?}; read {:?}..",
            (0x41 + i as u8) as char,
            &bytes[..bytes.len().min(16)]
        );
        // The hole after each region reads as zeros.
        let hole = read_member(source.as_ref(), at + 4096, 512);
        assert!(hole.iter().all(|&b| b == 0), "hole after region {i}");
    }
    // The trailing hole runs to the real size.
    let tail = read_member(source.as_ref(), 1_048_576 - 512, 4096);
    assert_eq!(tail, vec![0u8; 512]);

    let after = entry_named(&out, "after.txt");
    let after_src = after.data.as_ref().unwrap();
    assert_eq!(
        read_member(after_src.as_ref(), 0, 64),
        b"the member after the sparse one\n"
    );
}

/// The API re-opens a member by path through `extract_tar_entry_source`; it
/// must serve the same bytes ingest does.
#[test]
fn a_gnu_sparse_member_reopened_by_path_serves_the_same_bytes() {
    let data = include_bytes!("../../tests/fixtures/gnu_sparse.tar").to_vec();
    let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));
    let reopened = extract_tar_entry_source(src, "disk.img").expect("re-opened");
    assert_eq!(reopened.size(), 1_048_576);
    assert_eq!(read_member(reopened.as_ref(), 65_536, 4), b"BBBB");
    assert_eq!(read_member(reopened.as_ref(), 4096, 4), vec![0u8; 4]);
}

/// The real file the defect was found on: dfir_ntfs's `vss_2_stor.tar.gz`,
/// one GNU sparse member `vss_2_stor.raw` of 5 GiB of which 13 MB is stored in
/// 58 regions. Every stored region must read back at its own offset.
#[test]
fn the_real_vss_sparse_member_serves_every_region_at_its_offset() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../reference/dfir_ntfs/test_data/vss_2_stor.tar.gz");
    let Ok(gz) = std::fs::read(&path) else {
        eprintln!("skipping: {} is not on this machine", path.display());
        return;
    };
    let mut tar_bytes = Vec::new();
    std::io::Read::read_to_end(&mut flate2::read::GzDecoder::new(&gz[..]), &mut tar_bytes).unwrap();

    // The map, read independently of the module: 4 slots in the header, then
    // 21 per extension block, each an octal offset and length of 12 bytes.
    let octal = |b: &[u8]| {
        let s = std::str::from_utf8(b)
            .unwrap()
            .trim_matches(|c: char| c == '\0' || c == ' ');
        if s.is_empty() {
            0
        } else {
            u64::from_str_radix(s, 8).unwrap()
        }
    };
    let mut map = Vec::new();
    for i in 0..4 {
        let at = 386 + i * 24;
        map.push((
            octal(&tar_bytes[at..at + 12]),
            octal(&tar_bytes[at + 12..at + 24]),
        ));
    }
    let mut extended = tar_bytes[482] != 0;
    let mut block = 512;
    while extended {
        for i in 0..21 {
            let at = block + i * 24;
            map.push((
                octal(&tar_bytes[at..at + 12]),
                octal(&tar_bytes[at + 12..at + 24]),
            ));
        }
        extended = tar_bytes[block + 504] != 0;
        block += 512;
    }
    map.retain(|&(_, len)| len > 0);
    assert_eq!(map.len(), 58);

    let out = TarExpanderModule
        .process(&container("vss_2_stor.tar", Some("tar"), tar_bytes.clone()))
        .unwrap();
    let member = entry_named(&out, "vss_2_stor.raw");
    assert_eq!(member.metadata["size"], json!(5_368_709_120u64));
    assert!(
        member.metadata.get("content_incomplete").is_none(),
        "{}",
        member.metadata
    );
    let source = member.data.as_ref().unwrap();
    let mut stored_at = block as u64;
    for &(offset, len) in &map {
        let served = read_member(source.as_ref(), offset, len as usize);
        assert!(
            served == tar_bytes[stored_at as usize..(stored_at + len) as usize],
            "region at {offset} ({len} bytes) is not the stored bytes"
        );
        stored_at += len;
    }
    // A hole between the first two regions reads as zeros.
    assert_eq!(read_member(source.as_ref(), 4096, 4096), vec![0u8; 4096]);
}

// ── bytes after the end-of-archive block (HUNT-206) ─────────────────────────

/// Two GNU tar archives joined with `cat`. GNU tar lists only the first
/// unless given `--ignore-zeros`; the walk stopped at the first end marker and
/// nothing said that a second archive followed it.
#[test]
fn bytes_after_the_end_of_archive_block_are_recorded() {
    let data = include_bytes!("../../tests/fixtures/concatenated.tar").to_vec();
    let out = TarExpanderModule
        .process(&container("joined.tar", Some("tar"), data))
        .unwrap();
    entry_named(&out, "first.txt");
    let status = status_records(&out);
    assert_eq!(status.len(), 1, "{out:?}");
    let m = &status[0].metadata;
    assert_eq!(
        m["content_incomplete_reason"],
        json!("tar_bytes_after_end_marker")
    );
    assert_eq!(m["inventory_incomplete"], json!(true));
    assert_eq!(m["trailing_bytes_offset"], json!(512 + 512 + 512));
    assert_eq!(m["trailing_bytes_after_end_marker"], json!(20_480 - 1536));
    assert_eq!(m["trailing_bytes_all_zero"], json!(false));
    assert_eq!(m["trailing_first_nonzero_offset"], json!(10_240));
    assert_eq!(m["trailing_tar_header_at"], json!(10_240));
}

/// The record padding GNU tar writes after the end marker (to a 10 KiB
/// record) is zeros and is not reported: `links.tar` ends that way.
#[test]
fn zero_record_padding_after_the_end_marker_is_not_reported() {
    let data = include_bytes!("../../tests/fixtures/links.tar").to_vec();
    assert!(data.len() > 2048 && data.len().is_multiple_of(10_240));
    let out = TarExpanderModule
        .process(&container("links.tar", Some("tar"), data))
        .unwrap();
    assert!(status_records(&out).is_empty(), "{out:?}");
}

/// The POSIX-format sparse members GNU tar writes (`--format=posix --sparse`,
/// sparse versions 0.0, 0.1 and 1.0) of the same 1 MiB file. The map is in
/// the PAX header (0.0: repeated `GNU.sparse.offset`/`numbytes`; 0.1:
/// `GNU.sparse.map`) or at the head of the member's data (1.0), the real size
/// in `GNU.sparse.size`/`realsize`, and for 0.1 and 1.0 the real name in
/// `GNU.sparse.name` while the header names `GNUSparseFile.<pid>/disk.img`.
/// Read as a plain file, the member was the packed regions (with, for 1.0,
/// the map text in front of them) under the stand-in name and stored size.
#[test]
fn a_posix_sparse_member_is_laid_out_from_its_map_in_every_version() {
    let fixtures: [(&str, &[u8]); 3] = [
        (
            "0.0",
            include_bytes!("../../tests/fixtures/pax_sparse_0.0.tar"),
        ),
        (
            "0.1",
            include_bytes!("../../tests/fixtures/pax_sparse_0.1.tar"),
        ),
        (
            "1.0",
            include_bytes!("../../tests/fixtures/pax_sparse_1.0.tar"),
        ),
    ];
    for (version, bytes) in fixtures {
        let out = TarExpanderModule
            .process(&container("pax.tar", Some("tar"), bytes.to_vec()))
            .unwrap();
        let member = out
            .iter()
            .find(|a| a.metadata["name"] == "disk.img")
            .unwrap_or_else(|| {
                panic!(
                    "{version}: no member named disk.img in {:?}",
                    out.iter().map(|a| &a.metadata["path"]).collect::<Vec<_>>()
                )
            });
        assert_eq!(member.metadata["path"], json!("/disk.img"), "{version}");
        assert_eq!(member.metadata["size"], json!(1_048_576), "{version}");
        assert!(
            member.metadata.get("content_incomplete").is_none(),
            "{version}: {}",
            member.metadata
        );
        let source = member.data.as_ref().expect("content");
        assert_eq!(source.size(), 1_048_576, "{version}");
        for (i, at) in [0u64, 65_536, 131_072, 262_144, 393_216, 520_192]
            .into_iter()
            .enumerate()
        {
            let bytes = read_member(source.as_ref(), at, 4096);
            assert!(
                bytes.len() == 4096 && bytes.iter().all(|&b| b == 0x41 + i as u8),
                "{version}: region {i} at {at}"
            );
            assert_eq!(
                read_member(source.as_ref(), at + 4096, 16),
                vec![0u8; 16],
                "{version}"
            );
        }
        let after = entry_named(&out, "after.txt");
        assert_eq!(
            read_member(after.data.as_ref().unwrap().as_ref(), 0, 64),
            b"the member after the sparse one\n",
            "{version}"
        );
    }
}
