//! The CLI `scan` path must not ingest an encrypted Apple disk image as a
//! silent zero-artifact no-op (LIVE-003).
//!
//! The HTTP ingest handler already surfaces `encrcdsa` images as a stated gap;
//! the CLI `scan` path was the second entry point that still ingested them
//! silently. This runs the shipped `seance scan` binary against a real
//! `encrcdsa`-magic file and asserts the run recognises it and says so, instead
//! of finishing with a silent "0 artifacts". That the warning fires proves the
//! scan consulted the shared detector, which stamps the encrypted /
//! content-incomplete markers the incompleteness census reads (those markers are
//! unit-tested in seance_api).

use std::io::Write;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

static COUNTER: AtomicU32 = AtomicU32::new(0);

fn scratch() -> std::path::PathBuf {
    let base = std::env::temp_dir().join(format!(
        "seance_encdmg_{}_{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&base).unwrap();
    base
}

#[test]
fn cli_scan_surfaces_an_encrypted_apple_dmg_instead_of_a_silent_no_op() {
    let dir = scratch();
    let ws = dir.join("ws");
    let img = dir.join("apfs_encrypted.dmg");

    // A minimal file carrying the 8-byte encrypted-Apple-disk-image magic; the
    // bytes after it are never decrypted.
    {
        let mut f = std::fs::File::create(&img).unwrap();
        f.write_all(b"encrcdsa").unwrap();
        f.write_all(&[0u8; 512]).unwrap();
    }

    let output = Command::new(env!("CARGO_BIN_EXE_seance"))
        .args(["--workspace"])
        .arg(&ws)
        .arg("scan")
        .arg("--path")
        .arg(&img)
        .output()
        .expect("run seance scan");
    assert!(
        output.status.success(),
        "scan should complete (the exhibit is recorded, not refused): stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    // The run must SAY the source is encrypted, not finish silently. The warning
    // lands in the workspace log; before the fix the CLI path ingested an
    // encrcdsa image with no mention of encryption anywhere.
    let log = std::fs::read_to_string(ws.join("seance.log")).unwrap_or_default();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        log.contains("encrypted Apple disk image") || stderr.contains("encrypted Apple disk image"),
        "the scan must surface the encrypted Apple disk image; \nlog:\n{log}\nstderr:\n{stderr}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
