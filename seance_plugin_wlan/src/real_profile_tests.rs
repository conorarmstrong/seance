//! A real Windows 10 wireless profile — `WLAN-1` in
//! `documentation/VALIDATION.md`, the known answer `WLAN-001` asked for.
//!
//! The file is LoneWolf's
//! `ProgramData/Microsoft/Wlansvc/Profiles/Interfaces/{4B0AE068-B350-4BD4-85AB-77E00E581863}/{4D7FCC2E-EF1B-4B7B-8143-9514F97A9AE3}.xml`
//! (inode 92655, 1,271 bytes, CRLF line ends, tab-indented, a `v3`-namespaced
//! `MacRandomization` element). It is not in the repository.
//! `SEANCE_WLAN_PROFILE` is its path: unset skips loudly, set-but-missing fails
//! (`seance_core::test_support::corpus`).
//!
//! Every expected value was read off the file without this crate: the XML by
//! eye, and the `keyMaterial` DPAPI blob decoded field by field by a separate
//! Python reading (version 1, provider `df9d8cd0-…`, master-key version 1,
//! master key `1fbfafc4-8882-463c-89ee-65cbdc18313a`, empty description,
//! `CALG_AES_256`, `CALG_SHA_512`, 16 bytes of ciphertext, 230 bytes in all).
//! The master-key file that GUID names is in the same image, at
//! `Windows/System32/Microsoft/Protect/S-1-5-18/User/` (inode 90938).

use super::*;
use seance_core::data_source::{DataSource, FileDataSource};
use seance_core::test_support::corpus;

const DIR: &str =
    "ProgramData/Microsoft/Wlansvc/Profiles/Interfaces/{4B0AE068-B350-4BD4-85AB-77E00E581863}";
const FILE: &str = "{4D7FCC2E-EF1B-4B7B-8143-9514F97A9AE3}.xml";

#[test]
fn lonewolf_net_2_4_is_read_as_windows_wrote_it() {
    let Some(path) = corpus::path("SEANCE_WLAN_PROFILE") else {
        return;
    };
    let src: Arc<dyn DataSource> =
        Arc::new(FileDataSource::new(path).expect("open the corpus file read-only"));
    // Shaped as the NTFS pipeline hands a file over.
    let art = Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(src),
        json!({ "name": FILE, "path": format!("{DIR}/{FILE}") }),
    );
    let out = WlanProfiles.process(&art).expect("the module runs");
    assert_eq!(out.len(), 1);
    let r = &out[0].metadata;

    assert_eq!(r["type"], "WifiNetwork");
    assert_eq!(r["profile_name"], "Net 2.4");
    assert_eq!(r["ssid"], "Net 2.4");
    assert_eq!(r["ssid_name"], "Net 2.4");
    assert_eq!(r["ssid_hex"], "4E657420322E34");
    assert_eq!(r["ssid_from_hex"], "Net 2.4");
    assert_eq!(r["ssid_forms_disagree"], false);
    assert!(r["hidden_network"].is_null(), "no nonBroadcast element");
    assert_eq!(r["connection_type"], "ESS");
    assert_eq!(r["connection_mode"], "auto");
    assert_eq!(r["connects_automatically"], true);
    assert_eq!(r["authentication"], "WPA2PSK");
    assert_eq!(r["encryption"], "AES");
    assert_eq!(r["uses_8021x"], false);
    assert_eq!(r["open_network"], false);
    assert_eq!(r["mac_randomisation"], false);
    assert_eq!(r["whole_document"], true);
    assert_eq!(r["unread_elements"], json!({}));
    assert_eq!(r["interface_guid"], "4b0ae068-b350-4bd4-85ab-77e00e581863");

    assert_eq!(r["key_state"], "dpapi_protected");
    assert_eq!(r["key_type"], "passPhrase");
    assert!(
        r["key"].is_null(),
        "a protected key is never presented as one"
    );
    let d = &r["key_dpapi"];
    assert_eq!(d["version"], 1);
    assert_eq!(d["master_key_version"], 1);
    assert_eq!(d["master_key_guid"], "1fbfafc4-8882-463c-89ee-65cbdc18313a");
    assert_eq!(d["description"], "");
    assert_eq!(d["blob_bytes"], 230);
    assert_eq!(d["ciphertext_bytes"], 16);
    assert_eq!(d["decrypted"], false);
    assert!(d["statement"].as_str().unwrap().contains(
        r"Windows\System32\Microsoft\Protect\S-1-5-18\User\1fbfafc4-8882-463c-89ee-65cbdc18313a"
    ));

    // The one shortfall is the encryption, and it is stated.
    assert_eq!(r["content_incomplete"], true);
    assert_eq!(r["content_incomplete_reason"], "encrypted");
}
