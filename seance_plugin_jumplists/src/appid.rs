//! The AppID in a jump list's file name, and which application it names.
//!
//! # How the ID is made, and how this table is built
//!
//! The sixteen hex digits in front of `.automaticDestinations-ms` are a
//! CRC-64 that Windows computes over the application's identifier: the
//! upper-cased UTF-16LE bytes of its AppUserModelID where it registers one,
//! or, where it does not, of its executable's path with the known folder in
//! front of it written as the folder's GUID (`{1AC14E77-…}\notepad.exe` for
//! `%windir%\system32\notepad.exe`). The parameters — the reflected
//! polynomial `0x92C64265D32139A4`, an all-ones initial value and no final
//! XOR — were established here by computing candidate identifiers and
//! comparing the results with IDs that are independently published: the
//! two real jump lists in plaso's test corpus, and the public "List of Jump
//! List IDs" reference. Twenty-one computed IDs agree with that list; none
//! disagrees.
//!
//! So the table below holds **identifiers**, not IDs. Every ID is computed
//! by this build from the identifier beside it, which means a wrong row is
//! inert: an identifier Windows never hashes produces an ID no file carries,
//! and can attribute nothing. The published list itself is not copied — its
//! licence is not stated on the page — and is cited only as the independent
//! check on rows marked `CrossChecked`. Rows marked `Computed` are
//! identifiers documented elsewhere (an inbox executable under its Microsoft
//! documented known folder) whose ID no independent source was found to
//! confirm; the record says which basis applies.
//!
//! An ID not in the table is reported as unknown. Nothing here guesses.

use std::collections::HashMap;
use std::sync::OnceLock;

/// How an identifier in the table is known, and therefore how far the
/// attribution can be trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Basis {
    /// The ID this build computes from the identifier agrees with an
    /// independently published ID for the same application.
    CrossChecked,
    /// The identifier is documented, but no independent publication of its
    /// ID was found to compare against.
    Computed,
}

impl Basis {
    pub fn describe(self) -> &'static str {
        match self {
            Basis::CrossChecked => {
                "CRC-64 of the application's identifier, computed by this build and cross-checked \
                 against an independently published jump-list ID for the same application"
            }
            Basis::Computed => {
                "CRC-64 of the application's documented identifier, computed by this build; no \
                 independently published ID was found to cross-check it against"
            }
        }
    }
}

/// One application this build can name.
#[derive(Debug, Clone, Copy)]
pub struct KnownApp {
    /// What Windows hashes: an AppUserModelID, or a known-folder path.
    pub identifier: &'static str,
    pub application: &'static str,
    pub basis: Basis,
}

const fn row(identifier: &'static str, application: &'static str, basis: Basis) -> KnownApp {
    KnownApp {
        identifier,
        application,
        basis,
    }
}

// Known-folder GUIDs, from Microsoft's KNOWNFOLDERID reference
// (learn.microsoft.com/windows/win32/shell/knownfolderid). Literals, because
// `concat!` takes nothing else.
macro_rules! system {
    ($rest:literal) => {
        concat!("{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\", $rest)
    };
}
macro_rules! system_x86 {
    ($rest:literal) => {
        concat!("{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}\\", $rest)
    };
}
macro_rules! windows {
    ($rest:literal) => {
        concat!("{F38BF404-1D43-42F2-9305-67DE0B28FC23}\\", $rest)
    };
}
macro_rules! program_files {
    ($rest:literal) => {
        concat!("{905E63B6-C1BF-494E-B29C-65B732D3D21A}\\", $rest)
    };
}
macro_rules! program_files_x86 {
    ($rest:literal) => {
        concat!("{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}\\", $rest)
    };
}

/// The applications this build can name, by the identifier Windows hashes.
pub const KNOWN_APPS: &[KnownApp] = &[
    // AppUserModelIDs the applications register.
    row(
        "Microsoft.Windows.Explorer",
        "Windows Explorer (Windows 8.1 and later)",
        Basis::CrossChecked,
    ),
    row(
        "Microsoft.Windows.ControlPanel",
        "Control Panel",
        Basis::CrossChecked,
    ),
    row(
        "Microsoft.InternetExplorer.Default",
        "Internet Explorer 8, 9 and 10 (32-bit)",
        Basis::CrossChecked,
    ),
    row(
        "Microsoft.Windows.RemoteDesktop",
        "Remote Desktop Connection",
        Basis::CrossChecked,
    ),
    row(
        "Microsoft.Windows.MediaPlayer32",
        "Windows Media Player 12 (32-bit)",
        Basis::CrossChecked,
    ),
    row("Chrome", "Google Chrome", Basis::CrossChecked),
    row(
        "Microsoft.MicrosoftEdge_8wekyb3d8bbwe!MicrosoftEdge",
        "Microsoft Edge (EdgeHTML)",
        Basis::CrossChecked,
    ),
    row(
        "Microsoft.Windows.Photos_8wekyb3d8bbwe!App",
        "Microsoft Photos",
        Basis::CrossChecked,
    ),
    // Inbox executables hashed by their known-folder path.
    row(
        windows!("explorer.exe"),
        "Windows Explorer (explorer.exe, Windows 7)",
        Basis::CrossChecked,
    ),
    row(
        system!("notepad.exe"),
        "Notepad (64-bit)",
        Basis::CrossChecked,
    ),
    row(
        system_x86!("notepad.exe"),
        "Notepad (32-bit)",
        Basis::CrossChecked,
    ),
    row(
        system!("mspaint.exe"),
        "Paint (mspaint.exe)",
        Basis::CrossChecked,
    ),
    row(
        system!("cmd.exe"),
        "Windows Command Processor (cmd.exe, 64-bit)",
        Basis::CrossChecked,
    ),
    row(
        system!("WindowsPowerShell\\v1.0\\powershell.exe"),
        "Windows PowerShell (64-bit)",
        Basis::CrossChecked,
    ),
    row(
        system_x86!("cmd.exe"),
        "Windows Command Processor (cmd.exe, 32-bit)",
        Basis::Computed,
    ),
    row(
        system_x86!("WindowsPowerShell\\v1.0\\powershell.exe"),
        "Windows PowerShell (32-bit)",
        Basis::Computed,
    ),
    row(
        system_x86!("mspaint.exe"),
        "Paint (mspaint.exe, 32-bit)",
        Basis::Computed,
    ),
    row(
        system!("mstsc.exe"),
        "Remote Desktop Connection (mstsc.exe)",
        Basis::Computed,
    ),
    row(
        windows!("regedit.exe"),
        "Registry Editor (regedit.exe)",
        Basis::Computed,
    ),
    row(
        system!("mmc.exe"),
        "Microsoft Management Console (mmc.exe)",
        Basis::Computed,
    ),
    row(
        system!("SnippingTool.exe"),
        "Snipping Tool",
        Basis::Computed,
    ),
    row(system!("taskmgr.exe"), "Task Manager", Basis::Computed),
    row(
        system!("calc.exe"),
        "Calculator (calc.exe)",
        Basis::Computed,
    ),
    row(
        system!("control.exe"),
        "Control Panel (control.exe)",
        Basis::Computed,
    ),
    row(
        program_files!("Windows NT\\Accessories\\wordpad.exe"),
        "WordPad (64-bit)",
        Basis::Computed,
    ),
    row(
        program_files_x86!("Windows NT\\Accessories\\wordpad.exe"),
        "WordPad (32-bit)",
        Basis::Computed,
    ),
    row(
        program_files!("Internet Explorer\\iexplore.exe"),
        "Internet Explorer (iexplore.exe, 64-bit)",
        Basis::Computed,
    ),
    row(
        program_files_x86!("Internet Explorer\\iexplore.exe"),
        "Internet Explorer (iexplore.exe, 32-bit)",
        Basis::Computed,
    ),
    row(
        program_files!("Windows Media Player\\wmplayer.exe"),
        "Windows Media Player (wmplayer.exe, 64-bit)",
        Basis::Computed,
    ),
    row(
        program_files_x86!("Windows Media Player\\wmplayer.exe"),
        "Windows Media Player (wmplayer.exe, 32-bit)",
        Basis::Computed,
    ),
    // Third-party executables that registered no AppUserModelID in the
    // builds the public list records.
    row(
        program_files_x86!("Mozilla Firefox\\firefox.exe"),
        "Mozilla Firefox (firefox.exe, 32-bit, a build registering no AppUserModelID)",
        Basis::CrossChecked,
    ),
    row(
        program_files_x86!("Notepad++\\notepad++.exe"),
        "Notepad++ (32-bit)",
        Basis::CrossChecked,
    ),
    row(
        program_files_x86!("VideoLAN\\VLC\\vlc.exe"),
        "VLC media player (32-bit)",
        Basis::CrossChecked,
    ),
    row(
        program_files_x86!("WinRAR\\WinRAR.exe"),
        "WinRAR (32-bit)",
        Basis::CrossChecked,
    ),
    row(
        program_files_x86!("Adobe\\Acrobat Reader DC\\Reader\\AcroRd32.exe"),
        "Adobe Acrobat Reader DC (32-bit)",
        Basis::CrossChecked,
    ),
    row(
        program_files!("Mozilla Firefox\\firefox.exe"),
        "Mozilla Firefox (firefox.exe, 64-bit, a build registering no AppUserModelID)",
        Basis::Computed,
    ),
    row(
        program_files!("Notepad++\\notepad++.exe"),
        "Notepad++ (64-bit)",
        Basis::Computed,
    ),
    row(
        program_files!("VideoLAN\\VLC\\vlc.exe"),
        "VLC media player (64-bit)",
        Basis::Computed,
    ),
    row(
        program_files!("WinRAR\\WinRAR.exe"),
        "WinRAR (64-bit)",
        Basis::Computed,
    ),
    row(
        program_files!("7-Zip\\7zFM.exe"),
        "7-Zip File Manager (64-bit)",
        Basis::Computed,
    ),
    row(
        program_files_x86!("7-Zip\\7zFM.exe"),
        "7-Zip File Manager (32-bit)",
        Basis::Computed,
    ),
];

/// The reflected form of the polynomial Windows uses for the AppID.
const POLY: u64 = 0x92C6_4265_D321_39A4;

fn crc_table() -> &'static [u64; 256] {
    static TABLE: OnceLock<[u64; 256]> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut t = [0u64; 256];
        for (i, slot) in t.iter_mut().enumerate() {
            let mut c = i as u64;
            for _ in 0..8 {
                c = if c & 1 == 1 { (c >> 1) ^ POLY } else { c >> 1 };
            }
            *slot = c;
        }
        t
    })
}

/// CRC-64 of the upper-cased UTF-16LE identifier, as Windows computes it.
pub fn app_id_of(identifier: &str) -> u64 {
    let table = crc_table();
    let mut crc = u64::MAX;
    for unit in identifier.to_uppercase().encode_utf16() {
        for byte in unit.to_le_bytes() {
            crc = table[((crc ^ byte as u64) & 0xFF) as usize] ^ (crc >> 8);
        }
    }
    crc
}

fn index() -> &'static HashMap<u64, &'static KnownApp> {
    static INDEX: OnceLock<HashMap<u64, &'static KnownApp>> = OnceLock::new();
    INDEX.get_or_init(|| {
        KNOWN_APPS
            .iter()
            .map(|app| (app_id_of(app.identifier), app))
            .collect()
    })
}

/// Resolve an AppID (up to sixteen hex digits, either case) to an
/// application. `None` is "unknown", and is the only other answer.
pub fn resolve(app_id: &str) -> Option<&'static KnownApp> {
    if app_id.is_empty() || app_id.len() > 16 {
        return None;
    }
    let id = u64::from_str_radix(app_id, 16).ok()?;
    index().get(&id).copied()
}

/// The AppID a jump list's file name carries, lower-cased and padded to
/// sixteen digits. `None` when the stem is not hex digits.
pub fn app_id_from_file_name(name: &str) -> Option<String> {
    let lower = name.to_ascii_lowercase();
    let stem = lower
        .strip_suffix(".automaticdestinations-ms")
        .or_else(|| lower.strip_suffix(".customdestinations-ms"))?;
    if stem.is_empty() || stem.len() > 16 || !stem.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(format!("{:0>16}", stem))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_hash_of_a_documented_app_user_model_id_is_its_published_app_id() {
        // The Windows 10 fixture in plaso's corpus is named 9d1f905ce5044aee;
        // the public jump-list ID lists give that as Edge, and Edge's
        // AppUserModelID hashes to it.
        assert_eq!(
            format!(
                "{:016x}",
                app_id_of("Microsoft.MicrosoftEdge_8wekyb3d8bbwe!MicrosoftEdge")
            ),
            "9d1f905ce5044aee"
        );
        assert_eq!(
            format!("{:016x}", app_id_of("Microsoft.Windows.Explorer")),
            "f01b4d95cf55d32a"
        );
        assert_eq!(
            format!("{:016x}", app_id_of("Microsoft.Windows.ControlPanel")),
            "7e4dca80246863e3"
        );
        assert_eq!(format!("{:016x}", app_id_of("Chrome")), "5d696d521de238c3");
    }

    #[test]
    fn the_hash_is_over_the_upper_cased_identifier_so_case_does_not_change_it() {
        assert_eq!(app_id_of("chrome"), app_id_of("CHROME"));
    }

    #[test]
    fn an_inbox_executable_is_hashed_by_its_known_folder_path() {
        // Notepad's two builds differ only in the known folder in front of
        // them, and the two public IDs differ accordingly.
        assert_eq!(
            format!(
                "{:016x}",
                app_id_of("{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\notepad.exe")
            ),
            "9b9cdc69c1c24e2b"
        );
        assert_eq!(
            format!(
                "{:016x}",
                app_id_of("{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}\\notepad.exe")
            ),
            "918e0ecb43d17e23"
        );
        assert_eq!(
            format!(
                "{:016x}",
                app_id_of("{F38BF404-1D43-42F2-9305-67DE0B28FC23}\\explorer.exe")
            ),
            "1b4dd67f29cb1962"
        );
    }

    #[test]
    fn a_known_app_id_resolves_and_an_unknown_one_is_unknown() {
        let app = resolve("1b4dd67f29cb1962").expect("Windows 7 Explorer");
        assert_eq!(
            app.application,
            "Windows Explorer (explorer.exe, Windows 7)"
        );
        assert_eq!(app.basis, Basis::CrossChecked);
        let app = resolve("9d1f905ce5044aee").expect("Edge");
        assert_eq!(app.application, "Microsoft Edge (EdgeHTML)");
        assert!(resolve("0000000000000000").is_none());
        assert!(resolve("ffffffffffffffff").is_none());
        // Upper-case digits are the same ID.
        assert!(resolve("1B4DD67F29CB1962").is_some());
    }

    #[test]
    fn every_table_row_hashes_to_a_distinct_id() {
        let mut seen = std::collections::HashSet::new();
        for row in KNOWN_APPS {
            assert!(
                seen.insert(app_id_of(row.identifier)),
                "two rows hash alike: {}",
                row.identifier
            );
        }
        assert!(KNOWN_APPS.len() >= 20);
    }

    #[test]
    fn the_app_id_is_the_sixteen_hex_digits_in_front_of_the_extension() {
        assert_eq!(
            app_id_from_file_name("1b4dd67f29cb1962.automaticDestinations-ms").as_deref(),
            Some("1b4dd67f29cb1962")
        );
        assert_eq!(
            app_id_from_file_name("C98DCE577F884EF8.customDestinations-ms").as_deref(),
            Some("c98dce577f884ef8")
        );
        // Paint's ID is published without its leading zero; the file name
        // carries it, and the lookup must not depend on which spelling the
        // examiner met first.
        assert_eq!(
            app_id_from_file_name("12dc1ea8e34b5a6.automaticDestinations-ms").as_deref(),
            Some("012dc1ea8e34b5a6")
        );
        assert!(app_id_from_file_name("notes.automaticDestinations-ms").is_none());
        assert!(app_id_from_file_name("1b4dd67f29cb1962.lnk").is_none());
    }
}
