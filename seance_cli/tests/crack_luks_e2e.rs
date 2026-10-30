//! End-to-end LUKS password recovery against a REAL LUKS volume.
//!
//! This is the strong validation of the whole password-recovery engine: it
//! builds an actual LUKS2 container with `cryptsetup`, then runs the shipped
//! `seance crack-luks` binary and asserts it recovers the passphrase — proving
//! the candidate generator, the engine, and the LUKS verifier work together on
//! evidence Séance did not itself create.
//!
//! Skips (does not fail) when `cryptsetup` is unavailable, so CI without it still
//! passes — the same corpus-gate discipline the rest of the tree uses.

use std::io::Write;
use std::process::Command;

fn have(cmd: &str) -> bool {
    Command::new("which")
        .arg(cmd)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Build a small LUKS2/PBKDF2 volume with a known passphrase. PBKDF2 with a low
/// iteration count keeps the test fast; the format is otherwise a real LUKS2
/// header that Séance's own reader parses.
fn make_luks_volume(dir: &std::path::Path, passphrase: &str) -> Option<std::path::PathBuf> {
    let img = dir.join("vol.luks");
    // 32 MiB is above the minimum LUKS2 metadata footprint.
    let f = std::fs::File::create(&img).ok()?;
    f.set_len(32 * 1024 * 1024).ok()?;
    drop(f);
    let mut child = Command::new("cryptsetup")
        .args([
            "luksFormat",
            "--type",
            "luks2",
            "--pbkdf",
            "pbkdf2",
            "--pbkdf-force-iterations",
            "1000",
            "--batch-mode",
        ])
        .arg(&img)
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    child
        .stdin
        .as_mut()?
        .write_all(passphrase.as_bytes())
        .ok()?;
    let status = child.wait().ok()?;
    if status.success() {
        Some(img)
    } else {
        None
    }
}

#[test]
fn crack_luks_recovers_a_real_passphrase_via_rule_mutation() {
    if !have("cryptsetup") {
        eprintln!("SKIP: cryptsetup not available");
        return;
    }
    let dir = tempdir();
    // The real passphrase is a rule mutation of a dictionary word: the cracker
    // must capitalise and suffix "letmein" to reach "Letmein1".
    let passphrase = "Letmein1";
    let Some(vol) = make_luks_volume(&dir, passphrase) else {
        eprintln!("SKIP: could not create a LUKS volume (environment restriction)");
        return;
    };

    let wordlist = dir.join("words.txt");
    std::fs::write(&wordlist, "admin\nletmein\npassword\n").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_seance"))
        .args(["--workspace"])
        .arg(dir.join("ws"))
        .arg("crack-luks")
        .arg("--volume")
        .arg(&vol)
        .arg("--wordlist")
        .arg(&wordlist)
        .output()
        .expect("run seance crack-luks");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("RECOVERED") && stdout.contains(passphrase),
        "expected recovery of {passphrase}; got:\n{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn crack_luks_reports_failure_when_the_passphrase_is_absent() {
    if !have("cryptsetup") {
        eprintln!("SKIP: cryptsetup not available");
        return;
    }
    let dir = tempdir();
    let Some(vol) = make_luks_volume(&dir, "a-passphrase-not-in-the-list") else {
        eprintln!("SKIP: could not create a LUKS volume");
        return;
    };
    let wordlist = dir.join("words.txt");
    std::fs::write(&wordlist, "admin\nletmein\n").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_seance"))
        .args(["--workspace"])
        .arg(dir.join("ws"))
        .arg("crack-luks")
        .arg("--volume")
        .arg(&vol)
        .arg("--wordlist")
        .arg(&wordlist)
        .output()
        .expect("run seance crack-luks");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Not found"),
        "expected a miss; got:\n{stdout}"
    );
}

/// A unique temp dir without pulling in the `tempfile` crate for this one test.
fn tempdir() -> std::path::PathBuf {
    let base = std::env::temp_dir().join(format!(
        "seance_crack_e2e_{}_{}",
        std::process::id(),
        // A per-call counter keeps two tests in the same process distinct.
        COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&base).unwrap();
    base
}
static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
