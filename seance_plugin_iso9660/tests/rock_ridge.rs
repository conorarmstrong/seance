//! HUNT-176: Rock Ridge (RRIP over SUSP) on real discs.
//!
//! The fixtures were mastered by xorriso 1.5.6 in mkisofs emulation from one
//! source tree:
//!
//! ```text
//! xorriso -as mkisofs -R -V SEANCE_RR -o rr.iso src
//! xorriso -as mkisofs -R -J -joliet-long -V SEANCE_RRJ -o rrj.iso src
//! ```
//!
//! `src` holds `A Long Mixed-Case Name.txt` (mtime 2019-05-06 07:08:09 UTC),
//! a 184-character `nnn…n.dat`, a symlink `link-to-long` to the first file,
//! and `Documents/` (mode 0751) holding `deeper/lower.case` (mode 0600), all
//! owned by uid/gid 1000. `rr.iso` carries Rock Ridge and no Joliet; `rrj.iso`
//! carries both.

use flate2::read::GzDecoder;
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::DataSource;
use seance_core::module::ForensicsModule;
use seance_plugin_iso9660::Iso9660Parser;
use serde_json::{json, Value};
use std::io::Read;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug)]
struct Bytes(Vec<u8>);

impl DataSource for Bytes {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        let off = offset as usize;
        if off >= self.0.len() {
            return Ok(0);
        }
        let n = buf.len().min(self.0.len() - off);
        buf[..n].copy_from_slice(&self.0[off..off + n]);
        Ok(n)
    }
    fn size(&self) -> u64 {
        self.0.len() as u64
    }
}

fn fixture_bytes(fixture: &str) -> Vec<u8> {
    let path = format!("{}/tests/fixtures/{fixture}", env!("CARGO_MANIFEST_DIR"));
    let mut data = Vec::new();
    GzDecoder::new(std::fs::File::open(path).unwrap())
        .read_to_end(&mut data)
        .unwrap();
    data
}

fn walk(fixture: &str) -> Vec<Artifact> {
    walk_bytes(fixture_bytes(fixture))
}

fn walk_bytes(data: Vec<u8>) -> Vec<Artifact> {
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(Arc::new(Bytes(data)) as Arc<dyn DataSource>),
        json!({"filesystem_type": "ISO9660", "subtype": "iso9660"}),
    );
    Iso9660Parser.process(&art).unwrap()
}

fn entry<'a>(out: &'a [Artifact], path: &str) -> &'a Value {
    out.iter()
        .map(|a| &a.metadata)
        .find(|m| m["path"] == path)
        .unwrap_or_else(|| {
            panic!(
                "no entry at {path}; have {:?}",
                out.iter().map(|a| &a.metadata["path"]).collect::<Vec<_>>()
            )
        })
}

fn read_content(out: &[Artifact], path: &str) -> Vec<u8> {
    let a = out.iter().find(|a| a.metadata["path"] == path).unwrap();
    let ds = a.data.as_ref().expect("content");
    let mut buf = vec![0u8; ds.size() as usize];
    let n = ds.read_at(0, &mut buf).unwrap();
    buf.truncate(n);
    buf
}

#[test]
fn rock_ridge_names_are_read_on_a_disc_without_joliet() {
    let out = walk("rr.iso.gz");
    let long = entry(&out, "/A Long Mixed-Case Name.txt");
    assert_eq!(long["name_source"], "rock_ridge");
    assert_eq!(
        read_content(&out, "/A Long Mixed-Case Name.txt"),
        b"rock ridge keeps this name\n"
    );
    entry(&out, "/Documents/deeper/lower.case");
    // A name long enough that the tool continues it (NM with CONTINUE, and a
    // CE continuation area when the record's system-use area runs out).
    let dat = format!("/{}.dat", "n".repeat(180));
    assert_eq!(read_content(&out, &dat), b"long\n");
}

#[test]
fn rock_ridge_posix_attributes_and_times_are_read() {
    let out = walk("rr.iso.gz");
    let docs = entry(&out, "/Documents");
    assert_eq!(docs["mode"], 0o040751);
    assert_eq!(docs["uid"], 1000);
    assert_eq!(docs["gid"], 1000);
    let lower = entry(&out, "/Documents/deeper/lower.case");
    assert_eq!(lower["mode"], 0o100600);
    assert!(lower["nlink"].as_u64().is_some());
    let long = entry(&out, "/A Long Mixed-Case Name.txt");
    assert_eq!(long["modified"], "2019-05-06T07:08:09+00:00");
    assert!(long["accessed"].is_string(), "{long}");
    assert!(long["changed"].is_string(), "{long}");
}

#[test]
fn a_rock_ridge_symlink_carries_its_target() {
    let out = walk("rr.iso.gz");
    let link = entry(&out, "/link-to-long");
    assert_eq!(link["mode"].as_u64().unwrap() & 0o170000, 0o120000);
    assert_eq!(link["is_symlink"], true);
    assert_eq!(link["symlink_target"], "A Long Mixed-Case Name.txt");
}

/// When a disc carries both, the Rock Ridge tree is walked: its names are
/// the POSIX names, unbounded by Joliet's 64 UCS-2 characters, and only it
/// carries ownership, modes and link targets -- the choice the Linux kernel
/// makes too.
#[test]
fn rock_ridge_is_preferred_over_joliet() {
    let out = walk("rrj.iso.gz");
    let long = entry(&out, "/A Long Mixed-Case Name.txt");
    assert_eq!(long["name_source"], "rock_ridge");
    assert_eq!(entry(&out, "/Documents")["mode"], 0o040751);
    entry(&out, &format!("/{}.dat", "n".repeat(180)));
}

/// Deep-directory relocation: ISO 9660 allows eight levels, so a mastering
/// tool moves a deeper directory into a relocation directory and leaves a
/// `CL` placeholder where it belongs, marking the moved record `RE`. Made by
/// `xorriso -as mkisofs -R -rr_reloc_dir rr_moved -o rr_relocated.iso src`
/// over `src/1/2/3/4/5/6/7/8/9/10/bottom.txt` ("bottom\n").
#[test]
fn a_relocated_deep_directory_is_read_where_it_belongs() {
    let out = walk("rr_relocated.iso.gz");
    let deep = "/1/2/3/4/5/6/7/8/9/10/bottom.txt";
    assert_eq!(read_content(&out, deep), b"bottom\n");
    // The `CL` placeholder is `/1/…/8`, the eighth level: the directory named
    // `9` beneath it is the relocated one, read from its extent under
    // `rr_moved`. TEST-002: this asserted on `/…/8/9`, which is not the
    // placeholder, and so pinned nothing about it.
    let placeholder = entry(&out, "/1/2/3/4/5/6/7/8");
    assert_eq!(placeholder["is_directory"], true);
    assert!(
        placeholder["rock_ridge_relocated_from_lba"].is_u64(),
        "/1/2/3/4/5/6/7/8 is the CL placeholder: {placeholder}"
    );
    let relocated = entry(&out, "/1/2/3/4/5/6/7/8/9");
    assert_eq!(relocated["is_directory"], true);
    assert!(
        relocated.get("rock_ridge_relocated_from_lba").is_none(),
        "the relocated directory itself is not a placeholder: {relocated}"
    );
    assert!(
        !out.iter().any(|a| a.metadata["path"]
            .as_str()
            .is_some_and(|p| p.starts_with("/rr_moved/"))),
        "a relocated directory is listed where it belongs, not also under rr_moved: {:?}",
        out.iter().map(|a| &a.metadata["path"]).collect::<Vec<_>>()
    );
}

/// HUNT-211: the same disc with the relocated directory's first sector zeroed
/// (a damaged sector read back as zeros). The `CL` placeholder names that
/// extent, whose "." record now gives no length, so nothing under it can be
/// listed -- and the placeholder's own entry must say so, not read as an
/// empty directory.
#[test]
fn a_placeholder_whose_relocated_directory_is_unreadable_is_marked() {
    let mut data = fixture_bytes("rr_relocated.iso.gz");
    let placeholder_path = "/1/2/3/4/5/6/7/8";
    let intact = walk_bytes(data.clone());
    let before = entry(&intact, placeholder_path);
    assert!(
        before["rock_ridge_relocated_from_lba"].is_u64(),
        "{placeholder_path} is the CL placeholder: {before}"
    );
    let lba = before["extent_lba"].as_u64().unwrap() as usize;
    data[lba * 2048..(lba + 1) * 2048].fill(0);
    let out = walk_bytes(data);
    let placeholder = entry(&out, placeholder_path);
    assert_eq!(placeholder["is_directory"], true);
    assert_eq!(
        placeholder["directory_parse_incomplete"], true,
        "the placeholder whose target will not read reads as an empty directory: {placeholder}"
    );
    assert_eq!(
        placeholder["directory_parse_incomplete_reason"],
        "relocated_directory_unreadable"
    );
    assert!(out.iter().any(|a| a.metadata["type"] == "iso9660_walk"
        && a.metadata["directory_parse_incomplete"] == true));
}

/// A zisofs-compressed file (Rock Ridge `ZF`) is not decompressed: its extent
/// is served as recorded and flagged, never passed off as the file's bytes.
/// Made by `xorriso -outdev rr_zisofs.iso -rockridge on -joliet off -map src /
/// -set_filter_r --zisofs / -- -commit` over `compressible.txt` ("zisofs "
/// repeated 20,000 times).
#[test]
fn a_zisofs_file_is_flagged_not_served_as_plaintext() {
    let out = walk("rr_zisofs.iso.gz");
    let f = entry(&out, "/compressible.txt");
    assert_eq!(f["name_source"], "rock_ridge");
    assert_eq!(f["rock_ridge_entries_not_read"], json!(["ZF"]));
    assert_eq!(f["content_incomplete"], true);
    assert_eq!(f["content_incomplete_reason"], "compressed");
}
