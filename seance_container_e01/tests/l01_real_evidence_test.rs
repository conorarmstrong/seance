//! HUNT-144: a real EnCase logical evidence file's entries are enumerated,
//! graded against libewf's own listing and an independent export.
//!
//! The evidence is Digital Corpora's 2012 National Gallery DC scenario: five
//! EnCase 7.4.1.10 `.L01` acquisitions of one iPhone, and a plain zip export of
//! the same phone taken a minute after the last of them. None of it is in the
//! repository. Point `SEANCE_L01_CORPUS` at the directory holding them
//! (`documentation/VALIDATION.md` §L01-1 says where they come from); with it
//! unset the test says it compared nothing and skips, and with
//! `SEANCE_REQUIRE_CORPUS=1` it fails instead.
//!
//! Two answers are checked, and they are different kinds of answer:
//!
//! 1. **libewf's own reading.** Beside each `.L01` is `<name>.ewfinfo.txt`, the
//!    file tree `ewfinfo` (libewf 20140816) printed for it. Every entry it lists
//!    must be published with the same name at the same path, and nothing it
//!    does not list may be. This proves the walk is complete and faithful to
//!    libewf; it is not independent of libewf.
//! 2. **An independent export.** `Tracy-phone-logical-2012-07-15-1317.zip`
//!    holds the phone's 30 camera-roll JPEGs, exported by a different route.
//!    Each must match a published entry of the 07-15 L01 by name, size and
//!    MD5 of the bytes served. This is the check that the bytes are the file's.

use seance_container_e01::E01ContainerModule;
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::DataSource;
use seance_core::hashing::compute_hashes;
use seance_core::module::ForensicsModule;
use seance_core::test_support::corpus;
use serde_json::json;
use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;
use uuid::Uuid;

const L01S: [&str; 5] = [
    "tracy-phone-2012-07-05-1640",
    "Tracy-phone-2012-07-07-1446",
    "Tracy-phone-2012-07-08-1515",
    "Tracy-phone-2012-07-09-1644",
    "Tracy-phone-2012-07-15-1316",
];
const ZIP: &str = "Tracy-phone-logical-2012-07-15-1317.zip";

/// HUNT-250 known answers for one L01's placeholder bytes, read from the
/// `ewfexport` raw stream at each placeholder's offset; see the test.
#[derive(Clone, Copy)]
struct PlaceholderKnown {
    stem: &'static str,
    placeholders: usize,
    /// How many of their bytes are 0x00.
    zeros: usize,
    /// The sum of their bytes.
    sum: u64,
    /// The lowest-offset placeholder whose byte is not 0x00: (offset, byte).
    first_nonzero: (u64, u64),
}

const PLACEHOLDER_KNOWN: [PlaceholderKnown; 5] = [
    PlaceholderKnown {
        stem: "tracy-phone-2012-07-05-1640",
        placeholders: 609,
        zeros: 397,
        sum: 23_728,
        first_nonzero: (263_466, 111),
    },
    PlaceholderKnown {
        stem: "Tracy-phone-2012-07-07-1446",
        placeholders: 639,
        zeros: 418,
        sum: 24_755,
        first_nonzero: (273_786, 43),
    },
    PlaceholderKnown {
        stem: "Tracy-phone-2012-07-08-1515",
        placeholders: 639,
        zeros: 136,
        sum: 66_897,
        first_nonzero: (595_936, 99),
    },
    PlaceholderKnown {
        stem: "Tracy-phone-2012-07-09-1644",
        placeholders: 683,
        zeros: 131,
        sum: 73_721,
        first_nonzero: (595_936, 99),
    },
    PlaceholderKnown {
        stem: "Tracy-phone-2012-07-15-1316",
        placeholders: 745,
        zeros: 120,
        sum: 81_737,
        first_nonzero: (595_936, 99),
    },
];

/// The paths `ewfinfo` lists under "Single files", one per entry, as
/// `/`-joined names from the root. The listing indents each entry by one
/// space per level after a tab.
fn ewfinfo_paths(listing: &str) -> Vec<String> {
    let mut paths = Vec::new();
    let mut stack: Vec<String> = Vec::new();
    let mut in_tree = false;
    for line in listing.lines() {
        if line == "Single files" {
            in_tree = true;
            continue;
        }
        if !in_tree {
            continue;
        }
        let Some(rest) = line.strip_prefix('\t') else {
            if line.is_empty() {
                continue;
            }
            break;
        };
        let depth = rest.len() - rest.trim_start_matches(' ').len();
        let name = &rest[depth..];
        assert!(
            depth <= stack.len(),
            "listing line {line:?} skips a level (depth {depth} under {})",
            stack.len()
        );
        stack.truncate(depth);
        stack.push(name.to_string());
        paths.push(format!("/{}", stack.join("/")));
    }
    paths
}

fn container(path: &Path) -> Artifact {
    let name = path.file_name().unwrap().to_string_lossy().into_owned();
    Artifact::new(
        Uuid::new_v4(),
        ArtifactType::Container,
        None,
        json!({ "name": name, "path": path.to_string_lossy(), "subtype": "e01" }),
    )
}

fn read_all(src: &dyn DataSource) -> Vec<u8> {
    let mut out = vec![0u8; src.size() as usize];
    let mut done = 0;
    while done < out.len() {
        match src.read_at(done as u64, &mut out[done..]) {
            Ok(0) => break,
            Ok(n) => done += n,
            Err(e) => panic!("read failed at {done}: {e}"),
        }
    }
    out.truncate(done);
    out
}

fn use_helper(isolated: bool) {
    std::env::set_var("SEANCE_EWF_HELPER", env!("CARGO_BIN_EXE_seance-ewf-helper"));
    std::env::set_var(
        "SEANCE_E01_ISOLATED",
        if isolated { "true" } else { "false" },
    );
}

fn entries(out: &[Artifact]) -> Vec<&Artifact> {
    out.iter()
        .filter(|a| a.artifact_type == ArtifactType::FileEntry)
        .collect()
}

fn s<'a>(a: &'a Artifact, key: &str) -> &'a str {
    a.metadata[key].as_str().unwrap_or_default()
}

/// One test, not several: the isolation switch is process environment, and
/// tests in one binary run on parallel threads.
#[test]
fn a_real_l01_is_enumerated_as_libewf_lists_it_and_serves_the_exported_bytes() {
    let Some(dir) = corpus::dir("SEANCE_L01_CORPUS") else {
        return;
    };
    use_helper(true);

    let mut listed_total = 0usize;
    let mut matched_total = 0usize;
    let mut bytes_checked = 0u64;
    let mut files_read = 0usize;
    let mut stored_md5_checked = 0usize;
    let (mut dir_data_total, mut dir_data_bytes) = (0usize, 0u64);
    for stem in L01S {
        let l01 = dir.join(format!("{stem}.L01"));
        let listing = std::fs::read_to_string(dir.join(format!("{stem}.ewfinfo.txt")))
            .expect("the libewf listing is kept beside each L01");
        let expected = ewfinfo_paths(&listing);
        assert!(
            !expected.is_empty(),
            "{stem}: the listing parsed to nothing"
        );

        let exhibit = container(&l01);
        let out = E01ContainerModule
            .process(&exhibit)
            .unwrap_or_else(|e| panic!("{stem}: process failed: {e:?}"));
        let all = entries(&out);
        // HUNT-246: the data EnCase stores against a directory entry is its
        // own record, a stream beside the directory; the listing is compared
        // against the entries, not against those streams.
        let (dir_data, published): (Vec<&Artifact>, Vec<&Artifact>) = all
            .into_iter()
            .partition(|a| a.metadata["l01_record_kind"] == json!("directory_data"));

        // Multisets: sibling names may repeat, so a path can occur twice.
        let mut want: BTreeMap<&str, usize> = BTreeMap::new();
        for p in &expected {
            *want.entry(p.as_str()).or_default() += 1;
        }
        let mut got: BTreeMap<&str, usize> = BTreeMap::new();
        for a in &published {
            *got.entry(s(a, "path")).or_default() += 1;
        }
        let matched: usize = want
            .iter()
            .map(|(p, n)| (*n).min(got.get(p).copied().unwrap_or(0)))
            .sum();
        let missing: Vec<_> = want
            .iter()
            .filter(|(p, n)| got.get(*p).copied().unwrap_or(0) < **n)
            .take(5)
            .collect();
        let extra: Vec<_> = got
            .iter()
            .filter(|(p, n)| want.get(*p).copied().unwrap_or(0) < **n)
            .take(5)
            .collect();
        eprintln!(
            "{stem}: libewf lists {} entries; {} published; {matched} match by path",
            expected.len(),
            published.len()
        );
        assert_eq!(
            matched,
            expected.len(),
            "{stem}: {matched} of {} entries libewf lists were published at the same path; \
             first missing: {missing:?}; out of {} published",
            expected.len(),
            published.len()
        );
        assert_eq!(
            published.len(),
            expected.len(),
            "{stem}: published entries libewf does not list: {extra:?}"
        );
        listed_total += expected.len();
        matched_total += matched;

        for a in &published {
            let path = s(a, "path");
            assert_eq!(
                Some(s(a, "name")),
                path.rsplit('/').next(),
                "the name is the path's last component"
            );
            assert_eq!(a.parent_id, Some(exhibit.id), "{path}: parented to the L01");
            // Every file's bytes are served in full, to the size the L01
            // records, and match the MD5 it stores where it stores one.
            if a.metadata["is_directory"] == json!(true) {
                assert!(a.data.is_none(), "{path}: a directory has no bytes");
                continue;
            }
            let size = a.metadata["size"].as_u64().expect("a file has a size");
            let Some(src) = a.data.as_ref() else {
                assert_eq!(
                    a.metadata["content_incomplete"],
                    json!(true),
                    "{path}: a file with no data source must say why"
                );
                continue;
            };
            let bytes = read_all(src.as_ref());
            assert_eq!(bytes.len() as u64, size, "{path}: short content");
            if let Some(md5) = a.metadata["stored_md5"].as_str() {
                assert_eq!(compute_hashes(&bytes).md5, md5, "{path}: stored MD5");
                stored_md5_checked += 1;
            }
            files_read += 1;
            bytes_checked += size;
        }

        let inventory = out
            .iter()
            .find(|a| a.metadata["type"] == json!("LogicalEvidenceInventory"))
            .expect("one inventory record per L01");
        assert_eq!(
            inventory.metadata["e01_open_mode"],
            json!("isolated_helper")
        );
        assert_eq!(
            inventory.metadata["entries_published"],
            json!(published.len())
        );
        assert_eq!(inventory.metadata["walk_incomplete"], json!(false));

        // What this corpus is known to hold, pinned so a change shows. Every
        // L01 time is 0 — unrecorded — so nothing is projected as a time.
        assert!(
            published.iter().all(|a| a.metadata.get("created").is_none()
                && a.metadata.get("modified").is_none()
                && a.metadata.get("accessed").is_none()
                && a.metadata.get("changed").is_none()),
            "{stem}: an L01 time of 0 must not be projected"
        );

        // HUNT-246: every directory whose recorded size equals the data it
        // stores has that data served as a `<dir>:l01_directory_data` stream,
        // in full, undecoded; a directory that records no size and stores one
        // byte (libewf's empty-entry form) is counted, not served.
        let dirs_with_sized_data = published
            .iter()
            .filter(|a| {
                a.metadata["is_directory"] == json!(true)
                    && a.metadata["size"].as_u64().is_some_and(|n| n > 0)
                    && a.metadata["l01_media_data_size"] == a.metadata["size"]
            })
            .count();
        assert!(dirs_with_sized_data > 0, "{stem}");
        assert_eq!(
            dir_data.len(),
            dirs_with_sized_data,
            "{stem}: one stream per directory whose stored data has a recorded size"
        );
        assert_eq!(
            inventory.metadata["directory_data_streams_published"],
            json!(dir_data.len())
        );
        for d in &dir_data {
            let of = s(d, "l01_directory_data_of");
            assert_eq!(s(d, "path"), format!("{of}:l01_directory_data"));
            assert_eq!(d.metadata["l01_directory_data_decoded"], json!(false));
            assert_eq!(d.metadata["is_directory"], json!(false));
            let bytes = read_all(d.data.as_ref().expect("the stream is served").as_ref());
            assert_eq!(
                bytes.len() as u64,
                d.metadata["size"].as_u64().unwrap(),
                "{of}"
            );
            dir_data_bytes += bytes.len() as u64;
        }
        dir_data_total += dir_data.len();
        let placeholders = published
            .iter()
            .filter(|a| a.metadata["l01_directory_placeholder_byte"] == json!(true))
            .count();
        assert_eq!(
            inventory.metadata["directory_placeholder_bytes_not_served"],
            json!(placeholders)
        );
        assert!(inventory
            .metadata
            .get("directories_with_data_not_served")
            .is_none());

        // HUNT-250: every placeholder's one byte was read and is recorded as a
        // value. Measured on this corpus, not a claim about L01s in general:
        // the stored spans of the published entries (placeholders included)
        // abut exactly, with no gap and no overlap, and the last ends at the
        // media size, so each placeholder's byte is stored for that entry
        // alone. What the byte means stays unestablished.
        let placeholder_values: Vec<u64> = published
            .iter()
            .filter(|a| a.metadata["l01_directory_placeholder_byte"] == json!(true))
            .map(|a| {
                a.metadata["l01_directory_placeholder_value"]
                    .as_u64()
                    .unwrap_or_else(|| panic!("{stem}: no value for {}", s(a, "path")))
            })
            .collect();
        assert!(!placeholder_values.is_empty(), "{stem}");
        // The values themselves, pinned so a read at the wrong offset fails.
        // Derived by reading `ewfexport -u -f raw` output of each L01 (the
        // whole media stream, sequentially) at every placeholder's recorded
        // offset: that is the same library by a different read path, not an
        // independent implementation. A one-byte shift changes 525 to 714 of
        // the values per file.
        let PlaceholderKnown {
            placeholders: count,
            zeros,
            sum,
            first_nonzero: (nz_off, nz_val),
            ..
        } = PLACEHOLDER_KNOWN
            .iter()
            .find(|k| k.stem == stem)
            .copied()
            .expect("a known answer per L01");
        assert_eq!(placeholder_values.len(), count, "{stem}: placeholders");
        assert_eq!(
            placeholder_values.iter().filter(|v| **v == 0).count(),
            zeros,
            "{stem}: placeholders whose byte is 0x00"
        );
        assert_eq!(
            placeholder_values.iter().sum::<u64>(),
            sum,
            "{stem}: sum of placeholder bytes"
        );
        let first_nonzero = published
            .iter()
            .filter(|a| a.metadata["l01_directory_placeholder_value"].as_u64() > Some(0))
            .map(|a| {
                (
                    a.metadata["l01_media_data_offset"].as_u64().unwrap(),
                    a.metadata["l01_directory_placeholder_value"]
                        .as_u64()
                        .unwrap(),
                )
            })
            .min();
        assert_eq!(first_nonzero, Some((nz_off, nz_val)), "{stem}");
        // With `SEANCE_L01_RAW_DIR` holding `<stem>.raw` (the ewfexport
        // output), every value is compared against that read.
        match std::env::var_os("SEANCE_L01_RAW_DIR") {
            Some(raw_dir) => {
                let raw = std::fs::read(Path::new(&raw_dir).join(format!("{stem}.raw")))
                    .unwrap_or_else(|e| panic!("{stem}: SEANCE_L01_RAW_DIR set, raw: {e}"));
                for a in published
                    .iter()
                    .filter(|a| a.metadata["l01_directory_placeholder_byte"] == json!(true))
                {
                    let off = a.metadata["l01_media_data_offset"].as_u64().unwrap() as usize;
                    assert_eq!(
                        a.metadata["l01_directory_placeholder_value"],
                        json!(raw[off]),
                        "{stem}: {} at {off}",
                        s(a, "path")
                    );
                }
                eprintln!("{stem}: every placeholder byte matches the ewfexport stream");
            }
            None => eprintln!(
                "{stem}: SEANCE_L01_RAW_DIR unset; placeholder bytes compared with the \
                 pinned summary only, not byte for byte"
            ),
        }
        // Every entry of the placeholder form is a directory: no file entry
        // records size 0 and stores one byte on these files.
        let file_placeholders: Vec<&str> = published
            .iter()
            .filter(|a| {
                a.metadata["is_directory"] == json!(false)
                    && a.metadata["size"] == json!(0)
                    && a.metadata["l01_media_data_size"] == json!(1)
            })
            .map(|a| s(a, "path"))
            .collect();
        assert!(
            file_placeholders.is_empty(),
            "{stem}: {file_placeholders:?}"
        );
        // The inventory checked each byte against every other stored span
        // (and every sparse entry's read at its duplicate offset), with no
        // entry's span unknown, and found it alone; the detail says so only
        // because of that check.
        assert_eq!(
            inventory.metadata["stored_spans_unknown"],
            json!(0),
            "{stem}"
        );
        assert_eq!(
            inventory.metadata["directory_placeholder_spans_checked"],
            json!(true)
        );
        assert_eq!(
            inventory.metadata["directory_placeholder_bytes_alone"],
            json!(count),
            "{stem}"
        );
        assert_eq!(
            inventory.metadata["directory_placeholder_bytes_in_shared_span"],
            json!(0),
            "{stem}"
        );
        assert_eq!(
            inventory.metadata["directory_placeholder_values_recorded"],
            json!(placeholder_values.len())
        );
        let mut spans: Vec<(u64, u64, String)> = published
            .iter()
            .filter_map(|a| {
                let off = a.metadata["l01_media_data_offset"].as_i64()?;
                let len = a.metadata["l01_media_data_size"].as_u64()?;
                (off >= 0 && len > 0).then(|| (off as u64, len, s(a, "path").to_string()))
            })
            .collect();
        spans.sort();
        assert_eq!(
            spans[0].0, 0,
            "{stem}: the first stored span starts the media"
        );
        for pair in spans.windows(2) {
            let (a_off, a_len, a_path) = &pair[0];
            let (b_off, _, b_path) = &pair[1];
            assert_eq!(
                a_off + a_len,
                *b_off,
                "{stem}: {a_path} and {b_path} do not abut"
            );
        }
        let (last_off, last_len, _) = spans.last().expect("stored spans");
        assert_eq!(
            json!(last_off + last_len),
            inventory.metadata["media_size"],
            "{stem}: the stored spans end at the media size"
        );
        eprintln!(
            "{stem}: {} placeholder values recorded; {} stored spans tile media \
             from {} to {}",
            placeholder_values.len(),
            spans.len(),
            spans[0].0,
            last_off + last_len
        );

        // HUNT-247: the one sparse entry per file stores 1 byte and names a
        // duplicate data offset; libewf reads its content from there. That is
        // the media offset of another entry whose stored MD5 is this entry's
        // stored MD5, and the bytes served hash to it, so the content is
        // established and not stamped unvalidated.
        let sparse: Vec<_> = published
            .iter()
            .filter(|a| {
                a.metadata["l01_flags"]
                    .as_u64()
                    .is_some_and(|f| f & 0x0400_0000 != 0)
            })
            .collect();
        assert_eq!(sparse.len(), 1, "{stem}: the one sparse entry");
        let sp = sparse[0];
        assert_eq!(
            s(sp, "l01_content_source"),
            "duplicate_data_offset",
            "{stem}: {}",
            sp.metadata
        );
        assert!(
            sp.metadata.get("content_incomplete").is_none(),
            "{stem}: {}",
            sp.metadata
        );
        let target = s(sp, "l01_duplicate_of_path");
        let t = published
            .iter()
            .find(|a| s(a, "path") == target)
            .expect("the entry the duplicate offset names is published");
        assert_eq!(
            t.metadata["l01_media_data_offset"],
            sp.metadata["l01_duplicate_media_data_offset"]
        );
        assert_eq!(s(t, "stored_md5"), s(sp, "stored_md5"));
        assert_eq!(s(sp, "l01_duplicate_content_check"), "stored_md5_matches");
        eprintln!(
            "{stem}: {} directory streams, {placeholders} one-byte placeholders; sparse {} -> {}",
            dir_data.len(),
            s(sp, "path"),
            target
        );
    }
    eprintln!(
        "directory data: {dir_data_total} streams served across 5 L01s ({dir_data_bytes} bytes)"
    );
    eprintln!(
        "libewf listings: {matched_total} of {listed_total} entries matched by path across 5 \
         L01s; {files_read} files read in full ({bytes_checked} bytes), \
         {stored_md5_checked} against a stored MD5"
    );

    // The independent answer: the zip export of the same phone.
    let last = dir.join(format!("{}.L01", L01S[4]));
    let out = E01ContainerModule.process(&container(&last)).unwrap();
    let published = entries(&out);
    let mut zip = zip::ZipArchive::new(std::fs::File::open(dir.join(ZIP)).unwrap()).unwrap();
    let (mut zip_files, mut matched) = (0usize, 0usize);
    for i in 0..zip.len() {
        let mut f = zip.by_index(i).unwrap();
        if f.is_dir() {
            continue;
        }
        zip_files += 1;
        let base = f.name().unwrap().rsplit('/').next().unwrap().to_string();
        let mut want = Vec::new();
        f.read_to_end(&mut want).unwrap();
        let want_md5 = compute_hashes(&want).md5;
        // The camera roll in the L01 is `.../DCIM/100APPLE/IMG_nnnn.JPG`, an
        // entry whose single sub-entry of the same name carries the bytes.
        let hits: Vec<_> = published
            .iter()
            .filter(|a| s(a, "name") == base && a.data.is_some() && s(a, "path").contains("/DCIM/"))
            .collect();
        let found = hits.iter().any(|a| {
            let got = read_all(a.data.as_ref().unwrap().as_ref());
            got.len() == want.len() && compute_hashes(&got).md5 == want_md5
        });
        if found {
            matched += 1;
        } else {
            eprintln!(
                "zip {base}: no L01 entry with its size and MD5 ({} by name)",
                hits.len()
            );
        }
    }
    eprintln!(
        "zip export: {matched} of {zip_files} files matched an L01 entry by name, size and MD5"
    );
    assert_eq!(zip_files, 30, "the export holds 30 camera-roll JPEGs");
    assert_eq!(matched, zip_files);

    // HUNT-246: the 192-byte record EnCase stores beside a photo is served.
    // Its bytes carry the photo's name and its size as UTF-16LE text (read
    // independently from the media stream `ewfexport` wrote); it is published
    // undecoded, because what its four times record is not established.
    let rec = published
        .iter()
        .find(|a| s(a, "path").ends_with("/DCIM/100APPLE/IMG_0061.JPG:l01_directory_data"))
        .expect("the record beside IMG_0061.JPG");
    let bytes = read_all(rec.data.as_ref().unwrap().as_ref());
    assert_eq!(bytes.len(), 192);
    let utf16 = |t: &str| -> Vec<u8> { t.encode_utf16().flat_map(u16::to_le_bytes).collect() };
    for needle in ["IMG_0061.JPG", "595432"] {
        assert!(
            bytes
                .windows(needle.len() * 2)
                .any(|w| w == utf16(needle).as_slice()),
            "{needle}"
        );
    }
    assert_eq!(rec.metadata["l01_directory_data_decoded"], json!(false));

    // In process, the same walk and the same bytes.
    use_helper(false);
    let inproc = E01ContainerModule.process(&container(&last)).unwrap();
    let inproc_entries = entries(&inproc);
    assert_eq!(inproc_entries.len(), published.len());
    let inv = inproc
        .iter()
        .find(|a| a.metadata["type"] == json!("LogicalEvidenceInventory"))
        .unwrap();
    assert_eq!(inv.metadata["e01_open_mode"], json!("in_process"));
    let sample: Vec<_> = inproc_entries
        .iter()
        .zip(published.iter())
        .filter(|(a, _)| a.data.is_some())
        .step_by(97)
        .collect();
    for (a, b) in &sample {
        assert_eq!(s(a, "path"), s(b, "path"));
        assert_eq!(
            read_all(a.data.as_ref().unwrap().as_ref()),
            read_all(b.data.as_ref().unwrap().as_ref()),
            "{}: in-process and isolated bytes differ",
            s(a, "path")
        );
    }
    eprintln!(
        "in-process: {} entries, {} sampled files byte-identical to isolated",
        inproc_entries.len(),
        sample.len()
    );
    use_helper(true);
}
