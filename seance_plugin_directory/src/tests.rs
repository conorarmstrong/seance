use super::*;
use std::io::Write;

fn root_artifact(dir: &Path) -> Artifact {
    Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::RawEvidence,
        None,
        json!({
            "name": dir.file_name().unwrap().to_string_lossy(),
            "path": dir.to_string_lossy(),
            "is_directory": true,
        }),
    )
}

fn walk(dir: &Path) -> Vec<Artifact> {
    DirectoryWalkerModule::new()
        .process(&root_artifact(dir))
        .expect("walked")
}

fn file_named<'a>(out: &'a [Artifact], name: &str) -> &'a Artifact {
    out.iter()
        .find(|a| a.metadata["name"] == name)
        .unwrap_or_else(|| panic!("{name} is not in the listing"))
}

/// HUNT-096. An examiner receives half their material as a folder — an unpacked
/// extraction, a Takeout, a logical acquisition, a mounted share — and pointing
/// Séance at one produced a single artifact and nothing under it.
#[test]
fn a_folder_of_files_becomes_file_entries() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("data/system")).unwrap();
    let mut f = std::fs::File::create(dir.path().join("data/system/packages.list")).unwrap();
    f.write_all(b"com.example 10123").unwrap();
    std::fs::File::create(dir.path().join("readme.txt")).unwrap();

    let out = walk(dir.path());

    let packages = file_named(&out, "packages.list");
    assert_eq!(packages.metadata["path"], "/data/system/packages.list");
    assert_eq!(packages.metadata["parent_path"], "/data/system");
    assert_eq!(packages.metadata["is_directory"], json!(false));
    assert_eq!(packages.metadata["size"], 17);
    // The bytes are attached, so every downstream parser runs over them.
    assert!(packages.data.is_some());
    // And the file says where it came from, so the API can serve it later.
    assert!(packages.metadata["source_path"]
        .as_str()
        .unwrap()
        .ends_with("data/system/packages.list"));

    // The directories are listed too: the tree has to be navigable.
    let system = file_named(&out, "system");
    assert_eq!(system.metadata["is_directory"], json!(true));
    assert!(system.data.is_none());

    assert!(out.iter().any(|a| a.metadata["name"] == "readme.txt"));
}

/// A logical acquisition's only record of a file's history is what the
/// filesystem holds about it.
#[test]
fn the_filesystem_times_and_ownership_are_carried() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::File::create(dir.path().join("evidence.bin")).unwrap();

    let out = walk(dir.path());
    let file = file_named(&out, "evidence.bin");
    assert!(file.metadata["modified"].is_string(), "mtime is carried");
    #[cfg(unix)]
    {
        assert!(file.metadata["mode"].is_string());
        assert!(file.metadata["uid"].is_number());
        assert!(file.metadata["inode"].is_number());
    }
}

/// The access time of a folder handed to an examiner records when the COPY was
/// read — by the collection tool, by the examiner's own file manager, by this
/// walk — and almost never when the device's user opened the file. Written as
/// `accessed`, it becomes an "Accessed" timeline event dated to the moment of
/// ingest, and on the ChromeOS image it buried the case's real history under
/// 38,000 events describing the examination itself (HUNT-102).
#[test]
fn the_examination_does_not_write_itself_into_the_timeline() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::File::create(dir.path().join("evidence.bin")).unwrap();

    let out = walk(dir.path());
    let file = file_named(&out, "evidence.bin");

    assert!(
        file.metadata.get("accessed").is_none(),
        "an atime read from the copy must not become a device event"
    );
    assert!(file.metadata.get("created").is_none());
    // The values are still recorded — under names that say whose times they
    // are, so nothing is lost and nothing is misattributed.
    assert!(file.metadata["accessed_on_collection_media"].is_string());
    assert!(file.metadata["times_note"]
        .as_str()
        .unwrap()
        .contains("collection"));
}

/// Following a link leaves the evidence tree — a link to `/etc` would pull the
/// examiner's own machine into the case — and a loop never ends.
#[cfg(unix)]
#[test]
fn a_symlink_is_recorded_and_not_followed() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("real")).unwrap();
    std::fs::File::create(dir.path().join("real/inside.txt")).unwrap();
    std::os::unix::fs::symlink("/etc", dir.path().join("escape")).unwrap();
    // A loop: a link pointing at its own parent.
    std::os::unix::fs::symlink(dir.path(), dir.path().join("loop")).unwrap();

    let out = walk(dir.path());

    let escape = file_named(&out, "escape");
    assert_eq!(escape.metadata["is_symlink"], json!(true));
    assert_eq!(escape.metadata["symlink_target"], "/etc");
    assert_eq!(escape.metadata["content_omitted"], "symlink_not_followed");
    assert!(escape.data.is_none());
    // Nothing from outside the tree was pulled in, and the walk terminated.
    assert!(!out.iter().any(|a| a.metadata["name"] == "passwd"));
    assert!(out.iter().any(|a| a.metadata["name"] == "inside.txt"));
}

/// An iOS backup's files are content-addressed blobs that only its own
/// `Manifest.db` can name. Listing them as loose files beside the reader's
/// named output would put the same evidence in the case twice, once unusably.
#[test]
fn a_directory_another_parser_owns_is_left_to_it() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::File::create(dir.path().join("Manifest.plist")).unwrap();
    std::fs::File::create(dir.path().join("Info.plist")).unwrap();
    std::fs::create_dir(dir.path().join("ab")).unwrap();
    std::fs::File::create(dir.path().join("ab/abcdef0123456789")).unwrap();

    let out = walk(dir.path());
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].metadata["type"], "DirectoryWalkSkipped");
    assert_eq!(out[0].metadata["owner"], "iOS backup");
    // The blobs are NOT listed.
    assert!(!out.iter().any(|a| a.metadata["name"] == "abcdef0123456789"));
}

/// A directory that cannot be listed is not an empty directory, and the case
/// has to say which it met.
#[cfg(unix)]
#[test]
fn an_unreadable_directory_is_declared_not_skipped_in_silence() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let locked = dir.path().join("locked");
    std::fs::create_dir(&locked).unwrap();
    std::fs::File::create(locked.join("secret.txt")).unwrap();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();

    let out = walk(dir.path());
    let status = out
        .iter()
        .find(|a| a.metadata["type"] == "DirectoryWalkStatus");

    // Running as root defeats the permission bits; only assert when it held.
    if let Some(status) = status {
        assert_eq!(status.metadata["inventory_incomplete"], json!(true));
        assert_eq!(status.metadata["unreadable_directories"], 1);
        assert!(status.metadata["inventory_incomplete_detail"]
            .as_str()
            .unwrap()
            .contains("could not be listed"));
    }
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn a_file_is_not_a_directory_walk() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("image.dd");
    std::fs::File::create(&file).unwrap();
    let artifact = Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::RawEvidence,
        None,
        json!({"name": "image.dd", "path": file.to_string_lossy(), "is_directory": false}),
    );
    assert!(DirectoryWalkerModule::new()
        .process(&artifact)
        .unwrap()
        .is_empty());
}

/// HUNT-114. The walk produces one data source per file before any is read.
/// A deferred source opens on first read, not at creation, so a tree of
/// thousands of files does not hold a descriptor per file — past the host's
/// `ulimit -n`, an eager open fails and, swallowed, leaves a file the case
/// examined and found empty. Here: every file still carries its bytes, and a
/// sampled one reads correctly through its deferred source.
#[test]
fn a_large_tree_carries_every_file_and_content_survives() {
    let dir = tempfile::tempdir().unwrap();
    for i in 0..500 {
        let mut f = std::fs::File::create(dir.path().join(format!("f{i:04}.bin"))).unwrap();
        f.write_all(format!("content {i}").as_bytes()).unwrap();
    }

    let out = walk(dir.path());

    let files: Vec<_> = out
        .iter()
        .filter(|a| a.metadata["is_directory"] != json!(true))
        .collect();
    assert_eq!(files.len(), 500, "every file is a walked entry");
    assert!(
        files.iter().all(|a| a.data.is_some()),
        "every file carries a (deferred) data source, none lost to a descriptor limit"
    );

    let f42 = file_named(&out, "f0042.bin");
    let data = f42.data.as_ref().unwrap();
    let mut buf = vec![0u8; data.size() as usize];
    data.read_at(0, &mut buf).unwrap();
    assert_eq!(&buf, b"content 42");
}

/// A name that is not valid UTF-8 used to reach the case as though it had been
/// read: it passed every check, went through `to_string_lossy`, and was
/// counted nowhere — while the module header claimed "every undecodable name
/// is counted and declared".
///
/// A substituted name is a name an examiner cannot search for. The same class
/// as the ANSI shortcut paths in `seance_plugin_lnk`, which say which code
/// page they were read under.
// APFS refuses a name that is not valid UTF-8, so the file cannot be created on macOS.
#[cfg(all(unix, not(target_os = "macos")))]
#[test]
fn a_name_that_is_not_utf8_is_flagged_on_its_entry_and_counted_on_the_status() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let dir = tempfile::tempdir().expect("tempdir");
    // 0xFF is not valid UTF-8 in any position.
    let bad = OsStr::from_bytes(b"report\xff.docx");
    std::fs::write(dir.path().join(bad), b"x").expect("write");
    std::fs::write(dir.path().join("clean.txt"), b"y").expect("write");

    let out = walk(dir.path());

    // The entry is still emitted — the file exists and its bytes are reachable
    // — but its name says it was substituted.
    let lossy = out
        .iter()
        .find(|a| {
            a.metadata["name"]
                .as_str()
                .is_some_and(|n| n.contains('\u{FFFD}'))
        })
        .expect("the entry with the undecodable name");
    assert_eq!(lossy.metadata["name_read_lossily"], json!(true));
    let note = lossy.metadata["name_decode_note"].as_str().expect("a note");
    assert!(note.contains("NOT the name on the volume"), "{note}");
    assert!(
        note.contains("a search for it will not find the file"),
        "{note}"
    );
    // The bytes are still reachable, which is what makes the record usable.
    assert!(lossy.metadata["source_path"].as_str().is_some());

    // The clean name beside it claims nothing.
    let clean = file_named(&out, "clean.txt");
    assert!(clean.metadata.get("name_read_lossily").is_none());
    assert!(clean.metadata.get("name_decode_note").is_none());

    // And the walk is reported short, with the population.
    let status = out
        .iter()
        .find(|a| a.metadata["type"] == "DirectoryWalkStatus")
        .expect("a status record: a lossily-read name is a shortfall");
    assert_eq!(status.metadata["names_read_lossily"], json!(1));
    assert_eq!(
        status.metadata["unreadable_entries"],
        json!(0),
        "a lossy name is not an unreadable entry, and the two were the same counter"
    );
    let detail = status.metadata["inventory_incomplete_detail"]
        .as_str()
        .expect("a detail");
    assert!(detail.contains("not valid UTF-8"), "{detail}");
    assert!(detail.contains("name_read_lossily"), "{detail}");
}

/// And a clean tree raises no status record at all, so the flag above cannot
/// be read as background noise.
#[test]
fn a_tree_whose_every_name_decodes_reports_no_shortfall() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("a.txt"), b"a").expect("write");
    std::fs::write(dir.path().join("b.txt"), b"b").expect("write");

    let out = walk(dir.path());
    assert!(
        !out.iter()
            .any(|a| a.metadata["type"] == "DirectoryWalkStatus"),
        "a complete walk must not claim a shortfall"
    );
    assert!(out
        .iter()
        .all(|a| a.metadata.get("name_read_lossily").is_none()));
}
