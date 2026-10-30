use super::*;
use seance_core::data_source::{ByteSliceDataSource, DataSource};
use std::sync::Arc;

/// Build a `FileEntry` artifact with the given `name` + bytes and run `module`.
fn run<M: ForensicsModule>(module: &M, name: &str, bytes: Vec<u8>) -> Vec<Artifact> {
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": name }),
    );
    module.process(&art).unwrap()
}

// --- shell history -----------------------------------------------------------

#[test]
fn zsh_extended_history_parses_epoch_and_command() {
    let arts = run(
        &ShellHistoryParser,
        ".zsh_history",
        b": 1673000000:0;git status\n".to_vec(),
    );
    assert_eq!(arts.len(), 1);
    let m = &arts[0].metadata;
    assert_eq!(m["type"], "ShellHistoryEntry");
    assert_eq!(m["subtype"], "shell_history");
    assert_eq!(m["shell"], "zsh");
    assert_eq!(m["command"], "git status");
    assert_eq!(m["date"].as_i64(), Some(1_673_000_000));
    assert_eq!(m["line_number"].as_i64(), Some(1));
    // Records are parented to the source artifact.
    assert!(arts[0].parent_id.is_some());
    assert_eq!(arts[0].artifact_type, ArtifactType::ParsedRecord);
}

#[test]
fn plain_bash_line_yields_command_without_date() {
    let arts = run(&ShellHistoryParser, ".bash_history", b"ls -la\n".to_vec());
    assert_eq!(arts.len(), 1);
    let m = &arts[0].metadata;
    assert_eq!(m["shell"], "bash");
    assert_eq!(m["command"], "ls -la");
    assert!(m.get("date").is_none());
}

#[test]
fn bash_timestamp_comment_applies_to_next_command() {
    let arts = run(
        &ShellHistoryParser,
        ".bash_history",
        b"#1673000000\nwhoami\n".to_vec(),
    );
    // The `#<epoch>` line is metadata, not a command.
    assert_eq!(arts.len(), 1);
    let m = &arts[0].metadata;
    assert_eq!(m["shell"], "bash");
    assert_eq!(m["command"], "whoami");
    assert_eq!(m["date"].as_i64(), Some(1_673_000_000));
}

// --- linux trash -------------------------------------------------------------

#[test]
fn trashinfo_decodes_path_and_parses_date() {
    let arts = run(
        &LinuxTrashParser,
        "secret.txt.trashinfo",
        b"[Trash Info]\nPath=/home/user/secret%20file.txt\nDeletionDate=2023-01-05T14:30:00\n"
            .to_vec(),
    );
    assert_eq!(arts.len(), 1);
    let m = &arts[0].metadata;
    assert_eq!(m["type"], "TrashEntry");
    assert_eq!(m["subtype"], "linux_trash");
    assert_eq!(m["original_path"], "/home/user/secret file.txt");
    assert_eq!(m["name"], "secret file.txt");
    assert_eq!(m["deletion_date"], "2023-01-05T14:30:00");
    // 2023-01-05T14:30:00Z == 1672929000 Unix seconds.
    assert_eq!(m["date"].as_i64(), Some(1_672_929_000));
}

#[test]
fn trashinfo_applies_timezone_offset() {
    // A `DeletionDate` with a +02:00 offset must land two hours before the same
    // naive wall clock read as UTC: 14:30:00+02:00 == 12:30:00Z == 1672921800.
    let arts = run(
        &LinuxTrashParser,
        "east.txt.trashinfo",
        b"[Trash Info]\nPath=/home/user/east.txt\nDeletionDate=2023-01-05T14:30:00+02:00\n"
            .to_vec(),
    );
    assert_eq!(arts.len(), 1);
    assert_eq!(arts[0].metadata["date"].as_i64(), Some(1_672_921_800));

    // A -05:00 offset lands five hours after the naive value:
    // 14:30:00-05:00 == 19:30:00Z == 1672947000.
    let west = run(
        &LinuxTrashParser,
        "west.txt.trashinfo",
        b"[Trash Info]\nPath=/home/user/west.txt\nDeletionDate=2023-01-05T14:30:00-05:00\n"
            .to_vec(),
    );
    assert_eq!(west[0].metadata["date"].as_i64(), Some(1_672_947_000));

    // An explicit Z (and a naive value) are both UTC: 1672929000.
    let zulu = run(
        &LinuxTrashParser,
        "z.txt.trashinfo",
        b"[Trash Info]\nPath=/home/user/z.txt\nDeletionDate=2023-01-05T14:30:00Z\n".to_vec(),
    );
    assert_eq!(zulu[0].metadata["date"].as_i64(), Some(1_672_929_000));
}

// --- recent files ------------------------------------------------------------

#[test]
fn xbel_yields_uri_and_application() {
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<xbel version="1.0">
  <bookmark href="file:///home/user/report%20final.pdf" added="2023-02-01T10:00:00Z" modified="2023-02-02T11:00:00Z" visited="2023-02-03T12:00:00Z">
    <info>
      <metadata owner="http://freedesktop.org">
        <bookmark:applications>
          <bookmark:application name="Evince" exec="'evince %u'" count="3"/>
        </bookmark:applications>
      </metadata>
    </info>
  </bookmark>
</xbel>
"#;
    let arts = run(
        &RecentFilesParser,
        "recently-used.xbel",
        xml.as_bytes().to_vec(),
    );
    assert_eq!(arts.len(), 1);
    let m = &arts[0].metadata;
    assert_eq!(m["type"], "RecentFileEntry");
    assert_eq!(m["subtype"], "recent_file");
    assert_eq!(m["uri"], "/home/user/report final.pdf");
    assert_eq!(m["name"], "report final.pdf");
    assert_eq!(m["application"], "Evince");
    assert_eq!(m["added"], "2023-02-01T10:00:00Z");
    assert_eq!(m["modified"], "2023-02-02T11:00:00Z");
    assert_eq!(m["visited"], "2023-02-03T12:00:00Z");
}

// --- freedesktop thumbnails --------------------------------------------------

/// Build a minimal PNG carrying the given `tEXt` key/value chunks, followed by
/// an empty IDAT and IEND. CRCs are not validated by the parser, so they are
/// left zero.
fn png_with_text(entries: &[(&str, &str)]) -> Vec<u8> {
    let mut out = PNG_SIG.to_vec();
    let chunk = |ctype: &[u8; 4], data: &[u8], out: &mut Vec<u8>| {
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        out.extend_from_slice(ctype);
        out.extend_from_slice(data);
        out.extend_from_slice(&[0, 0, 0, 0]); // fake CRC
    };
    for (k, v) in entries {
        let mut d = k.as_bytes().to_vec();
        d.push(0);
        d.extend_from_slice(v.as_bytes());
        chunk(b"tEXt", &d, &mut out);
    }
    chunk(b"IDAT", &[], &mut out);
    chunk(b"IEND", &[], &mut out);
    out
}

#[test]
fn thumbnail_png_yields_uri_and_mtime() {
    let png = png_with_text(&[
        ("Thumb::URI", "file:///home/user/photos/holiday%20pic.jpg"),
        ("Thumb::MTime", "1673000000"),
        ("Thumb::Mimetype", "image/jpeg"),
        ("Software", "GNOME::ThumbnailFactory"),
    ]);
    let arts = run(&ThumbnailsParser, "a1b2c3.png", png);
    assert_eq!(arts.len(), 1);
    let m = &arts[0].metadata;
    assert_eq!(m["type"], "FreedesktopThumbnail");
    assert_eq!(m["original_path"], "/home/user/photos/holiday pic.jpg");
    assert_eq!(m["name"], "holiday pic.jpg");
    assert_eq!(m["source_mtime"].as_i64(), Some(1_673_000_000));
    assert_eq!(m["mime_type"], "image/jpeg");
    assert_eq!(m["software"], "GNOME::ThumbnailFactory");
}

#[test]
fn ordinary_png_without_thumb_uri_yields_nothing() {
    let png = png_with_text(&[("Comment", "just a picture")]);
    assert!(run(&ThumbnailsParser, "screenshot.png", png).is_empty());
    // Non-PNG content is ignored too.
    assert!(run(&ThumbnailsParser, "x.png", b"not a png".to_vec()).is_empty());
}

// --- self-selection ----------------------------------------------------------

#[test]
fn wrong_basename_yields_nothing() {
    assert!(run(&ShellHistoryParser, "notes.txt", b"ls\n".to_vec()).is_empty());
    assert!(run(
        &LinuxTrashParser,
        "readme.txt",
        b"[Trash Info]\nPath=/x\n".to_vec()
    )
    .is_empty());
    assert!(run(&RecentFilesParser, "bookmarks.xbel", b"<xbel/>".to_vec()).is_empty());
}

#[test]
fn module_ids_are_stable() {
    assert_eq!(ShellHistoryParser.id(), "plugin.os.shell_history");
    assert_eq!(LinuxTrashParser.id(), "plugin.os.linux_trash");
    assert_eq!(RecentFilesParser.id(), "plugin.os.recent_files");
    assert_eq!(ThumbnailsParser.id(), "plugin.os.freedesktop_thumbnails");
}

// --- Partial-read honesty (B2-110) -------------------------------------------

use seance_core::test_support::TruncatedSource;

fn run_short<M: ForensicsModule>(module: &M, name: &str, bytes: Vec<u8>) -> Vec<Artifact> {
    let declared = bytes.len() as u64 + 4096;
    let ds: Arc<dyn DataSource> = Arc::new(TruncatedSource::new(bytes, declared));
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": name }),
    );
    module.process(&art).unwrap()
}

/// A shell history read to its end must not claim commands were dropped.
#[test]
fn a_fully_read_shell_history_emits_no_incomplete_marker() {
    let out = run(
        &ShellHistoryParser,
        ".bash_history",
        b"ls -la\nwhoami\n".to_vec(),
    );
    assert!(!out
        .iter()
        .any(|a| a.metadata["type"] == "DesktopArtifactParseStatus"));
}

/// A shell history cut short yields a prefix of the commands the user typed;
/// without the marker the tail commands read as never having been run.
#[test]
fn a_short_read_shell_history_emits_an_incomplete_marker() {
    let out = run_short(
        &ShellHistoryParser,
        ".bash_history",
        b"ls -la\nwhoami\n".to_vec(),
    );
    let marker = out
        .iter()
        .find(|a| a.metadata["type"] == "DesktopArtifactParseStatus")
        .expect("short read must leave an incomplete marker");
    assert_eq!(marker.metadata["content_incomplete"], json!(true));
    assert_eq!(marker.metadata["content_incomplete_reason"], "short_read");
    assert_eq!(marker.metadata["artifact_kind"], "Shell history");
    assert_eq!(marker.metadata["entries_emitted"], json!(2));
}

/// The same honesty applies to the desktop bookmark inventory.
#[test]
fn a_short_read_xbel_emits_an_incomplete_marker() {
    let xbel = br#"<?xml version="1.0"?><xbel><bookmark href="file:///home/u/a.txt" added="2024-01-01T00:00:00Z"/></xbel>"#;
    let out = run_short(&RecentFilesParser, "recently-used.xbel", xbel.to_vec());
    let marker = out
        .iter()
        .find(|a| a.metadata["type"] == "DesktopArtifactParseStatus")
        .expect("short read must leave an incomplete marker");
    assert_eq!(marker.metadata["artifact_kind"], "Recently-used bookmarks");
    assert_eq!(marker.metadata["content_incomplete"], json!(true));
}

/// A `.trashinfo` cut short may have lost its `DeletionDate`; the record says so
/// rather than presenting an undated deletion.
#[test]
fn a_short_read_trashinfo_record_is_marked_incomplete() {
    let ti = b"[Trash Info]\nPath=/home/u/secret.txt\n".to_vec();
    let out = run_short(&LinuxTrashParser, "secret.txt.trashinfo", ti);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].metadata["content_incomplete"], json!(true));
    assert_eq!(out[0].metadata["content_incomplete_reason"], "short_read");
}

/// A file the parser refused to read past its own cap is not a broken image.
///
/// The two shortfalls are acted on differently: `cap_reached` is a decision this
/// tool made and can be raised, while `short_read` says the evidence could not
/// deliver bytes it claimed to hold — an acquisition fault an examiner will go
/// looking for. Reporting the first as the second sends them after a fault that
/// does not exist. Against the unfixed code this asserts `cap_reached` on a
/// record hard-coded to say `short_read`.
#[test]
fn an_over_cap_trashinfo_says_cap_reached_not_short_read() {
    let ds: Arc<dyn DataSource> = Arc::new(TruncatedSource::new(
        b"[Trash Info]\nPath=/home/u/secret.txt\n".to_vec(),
        MAX_TEXT_BYTES + 1,
    ));
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": "secret.txt.trashinfo" }),
    );
    let out = LinuxTrashParser.process(&art).unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].metadata["content_incomplete"], json!(true));
    assert_eq!(out[0].metadata["content_incomplete_reason"], "cap_reached");
    assert_eq!(out[0].metadata["declared_size"], json!(MAX_TEXT_BYTES + 1));
}

// --- B2-172: a thumbnail we could not read is not an ordinary picture --------
//
// The thumbnail path read `read_capped` with no shortfall check and walked the
// PNG chunks with bare `break`s. A `~/.cache/thumbnails` entry whose header was
// cut before `Thumb::URI` returned an empty vector — byte for byte the answer
// an ordinary screenshot gives. Thumbnails routinely outlive the files they
// depict, so losing one silently loses the only surviving evidence that a file
// existed.

#[test]
fn a_thumbnail_read_short_is_marked_incomplete() {
    // The URI is recovered, but the header ends before MTime/Mimetype would
    // have been read: their absence must not read as "the desktop recorded no
    // modification time".
    let png = png_with_text(&[
        ("Thumb::URI", "file:///home/user/secret.jpg"),
        ("Thumb::MTime", "1673000000"),
    ]);
    let arts = run_short(&ThumbnailsParser, "a1b2c3.png", png);
    assert_eq!(arts.len(), 1);
    let m = &arts[0].metadata;
    assert_eq!(m["type"], "FreedesktopThumbnail");
    assert_eq!(m["original_path"], "/home/user/secret.jpg");
    assert_eq!(m["content_incomplete"], json!(true));
    assert_eq!(m["content_incomplete_reason"], "short_read");
    assert!(m["declared_size"].as_u64().unwrap() > m["bytes_read"].as_u64().unwrap());
}

#[test]
fn a_png_cut_before_its_thumbnail_keys_is_reported_not_dismissed() {
    // Truncate the file inside the header, before any tEXt chunk is complete.
    // Without a marker this is indistinguishable from a screenshot.
    let mut png = png_with_text(&[("Thumb::URI", "file:///home/user/deleted-evidence.jpg")]);
    png.truncate(PNG_SIG.len() + 10);
    let arts = run(&ThumbnailsParser, "a1b2c3.png", png);

    assert_eq!(arts.len(), 1);
    let m = &arts[0].metadata;
    assert_eq!(m["type"], "DesktopArtifactParseStatus");
    assert_eq!(m["artifact_kind"], "FreedesktopThumbnail");
    assert_eq!(m["content_incomplete"], json!(true));
    assert_eq!(m["entries_emitted"], json!(0));
    // Every declared byte arrived; the file itself ends inside its header, so
    // this is a property of the evidence and not of the acquisition.
    assert_eq!(m["content_incomplete_reason"], "unresolved_structure");
}

/// HUNT-064. Windows Installer keeps rollback copies of files it replaces
/// under `Config.Msi\*.rbf`; a PNG icon among them ends inside its header and
/// gained a "freedesktop thumbnail, partially parsed" marker on a Windows
/// image that has never had a freedesktop thumbnail. A cut PNG at a known path
/// outside any thumbnail cache, with no `Thumb::` key read, is a cut PNG.
#[test]
fn a_cut_png_at_a_known_non_cache_path_is_not_reported_as_a_thumbnail() {
    let mut png = png_with_text(&[("Thumb::URI", "file:///home/user/deleted-evidence.jpg")]);
    png.truncate(PNG_SIG.len() + 10);
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(png.clone()));
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": "522cf5.rbf", "path": "/Config.Msi/522cf5.rbf" }),
    );
    assert!(ThumbnailsParser.process(&art).unwrap().is_empty());

    // The same bytes under a thumbnail cache are still reported.
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(png));
    let art = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        json!({ "name": "a1b2c3.png", "path": "/home/user/.cache/thumbnails/normal/a1b2c3.png" }),
    );
    let arts = ThumbnailsParser.process(&art).unwrap();
    assert_eq!(arts.len(), 1);
    let m = &arts[0].metadata;
    // And the sentence matches the reason: every byte arrived, the file ends
    // inside itself, so it was not "partly read".
    assert_eq!(m["content_incomplete_reason"], "unresolved_structure");
    let msg = m["message"].as_str().unwrap();
    assert!(msg.contains("whole file was read"), "{msg}");
    assert!(!msg.contains("Only part"), "{msg}");
}

#[test]
fn a_whole_ordinary_png_stays_completely_silent() {
    // The counterweight, and the reason the marker is gated on truncation: this
    // parser sees every PNG in the evidence, so a complete non-thumbnail must
    // produce nothing at all.
    let png = png_with_text(&[("Comment", "just a picture")]);
    assert!(run(&ThumbnailsParser, "screenshot.png", png).is_empty());
}

#[test]
fn a_whole_thumbnail_carries_no_incompleteness() {
    let png = png_with_text(&[
        ("Thumb::URI", "file:///home/user/pic.jpg"),
        ("Thumb::MTime", "1673000000"),
    ]);
    let arts = run(&ThumbnailsParser, "a1b2c3.png", png);
    assert_eq!(arts.len(), 1);
    assert!(arts[0].metadata.get("content_incomplete").is_none());
}

/// B7-018: a `.trashinfo` cut short before its `Path=` line used to return
/// nothing at all, so a deleted file vanished from the case entirely — the
/// record read as "this is not a trash record" rather than "this trash record
/// could not be read".
#[test]
fn a_trashinfo_cut_before_its_path_line_is_reported_not_dropped() {
    let ti = b"[Trash Info]\n".to_vec();
    let out = run_short(&LinuxTrashParser, "secret.txt.trashinfo", ti);
    assert_eq!(out.len(), 1, "a truncated trash record must not vanish");
    assert_eq!(out[0].metadata["type"], "DesktopArtifactParseStatus");
    assert_eq!(out[0].metadata["artifact_kind"], "linux_trash");
    assert_eq!(out[0].metadata["content_incomplete"], json!(true));
    assert_eq!(out[0].metadata["content_incomplete_reason"], "short_read");
}

/// The counterpart: a file read whole that carries no `Path=` really is not a
/// trash record, and must stay out of the case.
#[test]
fn a_complete_file_without_a_path_line_is_still_not_a_trash_record() {
    let out = run(
        &LinuxTrashParser,
        "notes.trashinfo",
        b"[Trash Info]\nDeletionDate=2024-01-01T00:00:00\n".to_vec(),
    );
    assert!(out.is_empty());
}
