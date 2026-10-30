//! Full chain against a real Windows 11 BitLocker disk: raw image → GPT
//! partition → BitLocker unlock by recovery password → NTFS → named files.
//!
//! # Why the chain and not the crypto
//!
//! `seance_plugin_bitlocker`'s own tests prove the key hierarchy and that
//! plaintext comes out. They do not prove the plaintext is *usable*, and for a
//! long time it was not: BitLocker puts its own boot record at sector 0 and
//! relocates the filesystem's, so a purely decrypting view has noise where the
//! NTFS boot sector belongs. Every parser downstream then reads that noise and
//! concludes the volume holds no filesystem — a fully recovered 61 GiB volume
//! that nothing can open, failing in the way an unformatted disk would rather
//! than in a way anyone would investigate.
//!
//! So this test asserts on the artifacts an examiner would actually be looking
//! for, by name, out the far end of the whole chain.
//!
//! # The corpus
//!
//! Windows 11 25H2 Enterprise Evaluation (build 26200), XTS-AES-256, built for
//! this purpose; the files below were planted deliberately before encryption
//! and their ground truth is recorded in `C:\seance-manifest.json` inside the
//! image. 64 GiB, so gitignored: put it at
//! `test_data/win11_bitlocker/win11-bitlocker-xts256.raw` or point
//! `SEANCE_WIN11_BITLOCKER_IMAGE` at it.
//!
//! # Why these are release-only
//!
//! Parsing the MFT means decrypting a large part of 61 GiB with AES-XTS, which
//! an unoptimised build makes unusably slow — a `cargo test --workspace` that
//! takes an hour is one nobody runs, and a suite nobody runs catches nothing.
//! They are ignored in debug and run under `--release`, where the whole file
//! takes about four minutes. `ignore` reports them as ignored, so a skipped run
//! is visible rather than looking like a pass.

use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::{DataSource, FileDataSource, WindowSource};
use seance_core::module::ForensicsModule;
use seance_plugin_bitlocker::{unlock_bitlocker, Credential};
use seance_plugin_mft::MftParser;
use std::sync::Arc;
use uuid::Uuid;

/// The BitLocker partition's offset and size, from the image's GPT.
const VOLUME_OFFSET: u64 = 407_896_064;
const VOLUME_LENGTH: u64 = 66_060_288_000;

const RECOVERY_PASSWORD: &str = "633281-498102-426096-319726-225203-245927-337876-444884";

fn corpus_image() -> Option<std::path::PathBuf> {
    if let Ok(p) = std::env::var("SEANCE_WIN11_BITLOCKER_IMAGE") {
        let p = std::path::PathBuf::from(p);
        return p.exists().then_some(p);
    }
    // Cargo runs the test binary from the package directory, so walk up to the
    // workspace root rather than assuming the current directory is it.
    let cwd = std::env::current_dir().ok()?;
    let root = if cwd.ends_with("seance_tests") {
        cwd.parent()?.to_path_buf()
    } else {
        cwd
    };
    let p = root.join("test_data/win11_bitlocker/win11-bitlocker-xts256.raw");
    p.exists().then_some(p)
}

/// Unlock the volume and hand the plaintext to the MFT parser, exactly as the
/// ingestion pipeline does.
fn parse_decrypted_volume() -> Option<Vec<Artifact>> {
    let path = corpus_image()?;
    let disk: Arc<dyn DataSource> = Arc::new(FileDataSource::new(path).expect("open image"));
    let volume: Arc<dyn DataSource> =
        Arc::new(WindowSource::new(disk, VOLUME_OFFSET, VOLUME_LENGTH));

    let unlocked = unlock_bitlocker(volume, &Credential::RecoveryKey(RECOVERY_PASSWORD.into()))
        .expect("the recovery password must unlock this volume");
    let plaintext = unlocked
        .decrypting_source
        .expect("an XTS volume must expose a decrypting source");

    let fs = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::FileSystem,
        Some(plaintext),
        serde_json::json!({
            "name": "ntfs", "subtype": "ntfs",
            "filesystem_type": "NTFS", "type": "FileSystem",
        }),
    );
    Some(MftParser::new().process(&fs).expect("MFT parse"))
}

/// The parse, done once for the whole test binary.
///
/// Every test here needs the same thing: the volume unlocked and its MFT
/// parsed. Doing it per test meant decrypting 61 GiB five times over — about
/// four minutes each — and a suite nobody would run is a suite that does not
/// catch anything. Cargo runs these as threads of one process, so a `OnceLock`
/// collapses it to a single pass.
static PARSED: std::sync::OnceLock<Option<Vec<Artifact>>> = std::sync::OnceLock::new();

fn parsed() -> Option<&'static Vec<Artifact>> {
    PARSED.get_or_init(parse_decrypted_volume).as_ref()
}

macro_rules! require_corpus {
    () => {
        match parsed() {
            Some(a) => a,
            None => {
                eprintln!(
                    "skipping: put the Windows 11 BitLocker corpus at \
                     test_data/win11_bitlocker/win11-bitlocker-xts256.raw \
                     (or set SEANCE_WIN11_BITLOCKER_IMAGE)"
                );
                return;
            }
        }
    };
}

fn names_of(artifacts: &[Artifact]) -> Vec<String> {
    artifacts
        .iter()
        .filter_map(|a| a.metadata.get("name").and_then(|v| v.as_str()))
        .map(|s| s.to_lowercase())
        .collect()
}

/// **The chain works end to end.** An encrypted disk and a recovery password
/// go in; a populated NTFS filesystem comes out.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "decrypts 61 GiB; unusably slow unoptimised — run with --release"
)]
fn an_encrypted_windows_11_disk_yields_a_populated_ntfs_filesystem() {
    let artifacts = require_corpus!();
    assert!(
        artifacts.len() > 1000,
        "a real Windows installation has tens of thousands of files; getting \
         {} means the volume decrypted but barely parsed",
        artifacts.len()
    );
}

/// The planted user documents must come back by name. These were written
/// before encryption and their hashes are in the manifest inside the image.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "decrypts 61 GiB; unusably slow unoptimised — run with --release"
)]
fn the_planted_user_documents_are_recovered_by_name() {
    let artifacts = require_corpus!();
    let names = names_of(artifacts);

    for expected in [
        "case-notes.txt",
        "budget-2026.csv",
        "passwords-reminder.txt",
        "installer-notes.md",
        "holiday-photo.jpg",
        "diagram.png",
    ] {
        assert!(
            names.iter().any(|n| n == expected),
            "planted file {expected} must be recovered from the decrypted \
             volume; it was written before encryption"
        );
    }
}

/// **Deleted files.** Two different deletions were planted because they leave
/// different traces, and the difference is the point:
///
/// - `recycled-report.txt` went to the Recycle Bin, which does not unlink the
///   data — it must be recoverable.
/// - `permanently-deleted.txt` was deleted outright. Its MFT record may still
///   exist, but its *content* was discarded by TRIM (the volume is on a
///   TRIM-capable virtual disk), so it must not be presented as recovered.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "decrypts 61 GiB; unusably slow unoptimised — run with --release"
)]
fn a_recycled_file_is_recovered_and_a_trimmed_one_is_not_invented() {
    let artifacts = require_corpus!();
    let names = names_of(artifacts);

    // Windows does not keep the original name in the Recycle Bin. It renames
    // the data to `$R<random><ext>` and writes a sibling `$I<random><ext>`
    // holding the original path and deletion time. Searching for the file's
    // own name finds nothing even though every byte of it is still there —
    // the recovery works through the `$I`/`$R` pair or not at all.
    let recycle_pairs: Vec<&String> = names
        .iter()
        .filter(|n| (n.starts_with("$r") || n.starts_with("$i")) && n.ends_with(".txt"))
        .collect();
    assert!(
        !recycle_pairs.is_empty(),
        "the recycled file must be found as its $I/$R pair; got no $I*.txt or \
         $R*.txt entries at all, which means the Recycle Bin was not reached"
    );

    // The permanently deleted file's MFT entry may survive; what must not
    // happen is content being reported for it, since TRIM discarded the
    // clusters. Verified independently: the file's body appears nowhere in the
    // decrypted volume.
    for a in artifacts {
        let name = a
            .metadata
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if name.eq_ignore_ascii_case("permanently-deleted.txt") {
            let has_content = a
                .metadata
                .get("content_incomplete")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            assert!(
                has_content || a.data.is_none(),
                "the clusters of this file were discarded by TRIM; its content \
                 must be marked incomplete rather than presented as recovered"
            );
        }
    }
}

/// The Edge browser database must survive the whole chain. It is the artifact
/// that makes this corpus useful to the SQLite plugins: a genuine Chromium
/// `History` database, written by a real browser that really fetched pages.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "decrypts 61 GiB; unusably slow unoptimised — run with --release"
)]
fn the_browser_history_database_survives_decryption() {
    let artifacts = require_corpus!();
    let names = names_of(artifacts);

    assert!(
        names.iter().any(|n| n == "history"),
        "Edge's History database must be recovered from the decrypted volume"
    );
}

/// Windows' own artifacts must be there too — not just what was planted. If
/// only the planted files appeared, the parse would be finding a handful of
/// records rather than a filesystem.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "decrypts 61 GiB; unusably slow unoptimised — run with --release"
)]
fn the_windows_installation_itself_is_present() {
    let artifacts = require_corpus!();
    let names = names_of(artifacts);

    for expected in ["$mft", "ntoskrnl.exe", "system"] {
        assert!(
            names.iter().any(|n| n == expected),
            "{expected} must be present; a real Windows volume has it"
        );
    }
}
