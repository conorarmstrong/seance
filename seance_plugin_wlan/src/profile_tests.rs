//! What a profile document states, and what it refuses to state.
//!
//! The fixtures are documents in the schema the WLAN service writes (the
//! schema is documented by Microsoft as `WLANProfile` v1, and is what `netsh
//! wlan export profile` produces). **No profile from a real Windows image was
//! available on the machine this was written on** — see `BUGS.md` — so these
//! grade the parser against the schema rather than against a seized file, and
//! the first real profile must be run through it before any claim is made
//! about its coverage.

use super::*;

/// A profile as the service writes one: WPA2-PSK, DPAPI-protected key.
fn protected_profile(key_material: &str) -> String {
    let ssid_hex = hex_of("Coffee Shop Guest");
    format!(
        r#"<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
	<name>Coffee Shop Guest</name>
	<SSIDConfig>
		<SSID>
			<hex>{ssid_hex}</hex>
			<name>Coffee Shop Guest</name>
		</SSID>
		<nonBroadcast>false</nonBroadcast>
	</SSIDConfig>
	<connectionType>ESS</connectionType>
	<connectionMode>auto</connectionMode>
	<autoSwitch>false</autoSwitch>
	<MSM>
		<security>
			<authEncryption>
				<authentication>WPA2PSK</authentication>
				<encryption>AES</encryption>
				<useOneX>false</useOneX>
			</authEncryption>
			<sharedKey>
				<keyType>passPhrase</keyType>
				<protected>true</protected>
				<keyMaterial>{key_material}</keyMaterial>
			</sharedKey>
		</security>
	</MSM>
	<MacRandomization xmlns="http://www.microsoft.com/networking/WLAN/profile/v3">
		<enableRandomization>false</enableRandomization>
	</MacRandomization>
</WLANProfile>
"#
    )
}

/// An SSID as the hex form Windows writes. Generated from the text rather
/// than typed: a hand-written hex string is a number nobody checked, and the
/// first version of this fixture carried one that decoded to "Coffee Shep
/// Gues".
fn hex_of(text: &str) -> String {
    text.as_bytes().iter().map(|b| format!("{b:02X}")).collect()
}

/// A DPAPI blob's hex, from the same fixture the DPAPI module's own tests
/// grade against.
fn blob_hex() -> String {
    crate::dpapi::test_support::blob_for_tests()
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect()
}

/// **Recognised by its root element and namespace**, and not by its path: a
/// profile exported to a desktop or carved out of free space is the same
/// document.
#[test]
fn a_profile_is_recognised_by_its_root_element_and_namespace() {
    let document = protected_profile("01");
    assert!(looks_like_profile(document.as_bytes()));
    // The first four kilobytes are what the module looks at, and the root
    // element is in them.
    assert!(looks_like_profile(&document.as_bytes()[..512]));
    assert!(!looks_like_profile(
        b"<?xml version=\"1.0\"?><plist></plist>"
    ));
    assert!(!looks_like_profile(
        b"a note about WLANProfile files and where they live"
    ));
    assert!(!looks_like_profile(b""));
}

/// Every field an examiner reads: the network, whether it was hidden, what it
/// was secured with, and whether the machine joined it without being asked.
#[test]
fn the_network_its_security_and_whether_it_joins_by_itself_are_read() {
    let parsed = parse(protected_profile(&blob_hex()).as_bytes()).expect("a profile");
    assert_eq!(parsed.profile_name, "Coffee Shop Guest");
    assert_eq!(parsed.ssid_name.as_deref(), Some("Coffee Shop Guest"));
    assert_eq!(parsed.hidden, Some(false));
    assert_eq!(parsed.connection_type.as_deref(), Some("ESS"));
    assert_eq!(parsed.connection_mode.as_deref(), Some("auto"));
    assert!(parsed.connects_automatically());
    assert_eq!(parsed.authentication.as_deref(), Some("WPA2PSK"));
    assert_eq!(parsed.encryption.as_deref(), Some("AES"));
    assert_eq!(parsed.uses_8021x, Some(false));
    assert_eq!(parsed.mac_randomisation, Some(false));
    assert!(!parsed.is_open());
    // `autoSwitch` is in the document and is not a field this build reads, so
    // it is counted rather than passed over in silence.
    assert_eq!(parsed.unread_elements.get("autoSwitch"), Some(&1));
    let json = parsed.to_json();
    assert_eq!(json["connects_automatically"], serde_json::json!(true));
    assert_eq!(json["open_network"], serde_json::json!(false));
    assert_eq!(json["join_times_available"], serde_json::json!(false));
    assert!(json["join_times_note"]
        .as_str()
        .is_some_and(|n| n.contains("WLAN-AutoConfig")));
}

/// **The two `name` elements are different fields.** The profile's name and
/// the SSID's are both `<name>`, at different depths, and reading them as one
/// field would file a renamed profile under the wrong network.
#[test]
fn the_profiles_name_and_the_ssids_name_are_not_confused() {
    let document = protected_profile("01").replace(
        "<name>Coffee Shop Guest</name>\n\t<SSIDConfig>",
        "<name>Renamed by the user</name>\n\t<SSIDConfig>",
    );
    let parsed = parse(document.as_bytes()).expect("a profile");
    assert_eq!(parsed.profile_name, "Renamed by the user");
    assert_eq!(parsed.ssid_name.as_deref(), Some("Coffee Shop Guest"));
    assert_eq!(
        parsed.ssid(),
        "Coffee Shop Guest",
        "a network is filed under its SSID, not under what the profile was renamed to"
    );
}

/// **A key in the clear is reported**, because it is the reason an examiner
/// opens the file, and the record says which of the two states it was in.
#[test]
fn a_key_in_the_clear_is_reported_as_being_in_the_clear() {
    let document = protected_profile("hunter2").replace(
        "<protected>true</protected>",
        "<protected>false</protected>",
    );
    let parsed = parse(document.as_bytes()).expect("a profile");
    match parsed.key.as_ref().expect("a key") {
        Key::Clear { key_type, key } => {
            assert_eq!(key_type, "passPhrase");
            assert_eq!(key, "hunter2");
        }
        other => panic!("{other:?}"),
    }
    let json = parsed.to_json();
    assert_eq!(json["key_state"], "in_the_clear");
    assert_eq!(json["key"], "hunter2");
    assert!(json["key_statement"]
        .as_str()
        .is_some_and(|s| s.contains("IN PLAIN TEXT")));
    // Nothing about a cleartext key is incomplete.
    assert!(!parsed
        .shortfalls()
        .iter()
        .any(|(reason, _)| *reason == IncompleteReason::Encrypted));
}

/// **A protected key is named, not omitted.** The record says which master
/// key it was encrypted under and exactly what recovering it would take —
/// omitting the field would read as a network with no key.
#[test]
fn a_protected_key_names_its_master_key_and_what_recovery_would_need() {
    let parsed = parse(protected_profile(&blob_hex()).as_bytes()).expect("a profile");
    let blob = match parsed.key.as_ref().expect("a key") {
        Key::Dpapi { blob, .. } => blob.clone(),
        other => panic!("{other:?}"),
    };
    assert_eq!(blob.master_key_guid, crate::dpapi::test_support::MASTER_KEY);
    let json = parsed.to_json();
    assert_eq!(json["key_state"], "dpapi_protected");
    assert!(
        json["key"].is_null(),
        "the passphrase is not in this record"
    );
    assert_eq!(json["key_dpapi"]["decrypted"], serde_json::json!(false));
    assert!(json["key_statement"]
        .as_str()
        .is_some_and(|s| s.contains("S-1-5-18")));
    assert!(parsed
        .shortfalls()
        .iter()
        .any(|(reason, _)| *reason == IncompleteReason::Encrypted));
}

/// A key the profile calls protected whose material this build cannot read is
/// counted as that, which is a third state and not either of the other two.
#[test]
fn a_protected_key_that_is_not_a_blob_this_build_reads_says_so() {
    let parsed = parse(protected_profile("NOTAVALIDBLOB00").as_bytes()).expect("a profile");
    match parsed.key.as_ref().expect("a key") {
        Key::ProtectedUnreadable { detail, .. } => {
            assert!(detail.contains("not a DPAPI blob"), "{detail}")
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(parsed.to_json()["key_state"], "protected_unreadable");
}

/// An open network is the finding an examiner reads first, and it is derived
/// from the two fields rather than from the absence of a key.
#[test]
fn an_open_network_is_named_as_one() {
    let document = protected_profile("01")
        .replace("<authentication>WPA2PSK</authentication>", "<authentication>open</authentication>")
        .replace("<encryption>AES</encryption>", "<encryption>none</encryption>")
        .replace(
            "<sharedKey>\n\t\t\t\t<keyType>passPhrase</keyType>\n\t\t\t\t<protected>true</protected>\n\t\t\t\t<keyMaterial>01</keyMaterial>\n\t\t\t</sharedKey>",
            "",
        );
    let parsed = parse(document.as_bytes()).expect("a profile");
    assert!(parsed.is_open());
    assert_eq!(parsed.key, Some(Key::None));
    assert_eq!(parsed.to_json()["open_network"], serde_json::json!(true));
    assert!(parsed.to_json()["key_statement"]
        .as_str()
        .is_some_and(|s| s.contains("no pre-shared key")));
}

/// **A hidden network is a claim about the machine, not just the network**: a
/// profile for one means this machine actively broadcast the name looking for
/// it, which is how a laptop's profile list leaks where it has been.
#[test]
fn a_hidden_network_is_recorded_as_hidden() {
    let document = protected_profile("01").replace(
        "<nonBroadcast>false</nonBroadcast>",
        "<nonBroadcast>true</nonBroadcast>",
    );
    let parsed = parse(document.as_bytes()).expect("a profile");
    assert_eq!(parsed.hidden, Some(true));
    assert_eq!(parsed.to_json()["hidden_network"], serde_json::json!(true));
}

/// **The SSID's two forms can disagree, and the hex is the authoritative
/// one.** An SSID is a byte string, so a name that renders as one network and
/// resolves as another is something somebody built.
#[test]
fn an_ssid_whose_two_forms_disagree_reports_both_and_prefers_the_bytes() {
    // The hex says "My Wi-Fi"; the <name> claims something else.
    let document = protected_profile("01").replace(
        &format!("<hex>{}</hex>", hex_of("Coffee Shop Guest")),
        &format!("<hex>{}</hex>", hex_of("My Wi-Fi")),
    );
    let parsed = parse(document.as_bytes()).expect("a profile");
    assert_eq!(parsed.ssid_from_hex.as_deref(), Some("My Wi-Fi"));
    assert_eq!(parsed.ssid_name.as_deref(), Some("Coffee Shop Guest"));
    assert!(parsed.ssid_forms_disagree);
    assert_eq!(
        parsed.ssid(),
        "My Wi-Fi",
        "the bytes are what the radio used"
    );
    let (reason, detail) = parsed
        .shortfalls()
        .into_iter()
        .find(|(_, d)| d.contains("two forms disagree"))
        .expect("the disagreement is on the record");
    assert_eq!(reason, IncompleteReason::UnresolvedStructure);
    assert!(detail.contains("authoritative"), "{detail}");
}

/// An SSID that is not valid UTF-8 keeps its hex and is not rendered as text
/// that was never on the air.
#[test]
fn an_ssid_that_is_not_text_keeps_its_hex() {
    let document = protected_profile("01").replace(
        &format!("<hex>{}</hex>", hex_of("Coffee Shop Guest")),
        "<hex>FFFE0001</hex>",
    );
    let parsed = parse(document.as_bytes()).expect("a profile");
    assert_eq!(parsed.ssid_hex.as_deref(), Some("FFFE0001"));
    assert_eq!(parsed.ssid_from_hex, None);
    assert!(
        !parsed.ssid_forms_disagree,
        "an SSID this build cannot render as text is not a disagreement with the name"
    );
    assert_eq!(parsed.ssid(), "Coffee Shop Guest");
}

/// **A document that stops part way through never presents as complete.** The
/// first version of this parser reported a file cut in half as a profile with
/// fewer fields, which is the exact failure this project exists to avoid.
#[test]
fn a_truncated_document_reports_what_it_read_and_that_it_failed() {
    let document = protected_profile(&blob_hex());
    // Cut where the security section begins, so what is asserted to be past
    // the cut is chosen rather than left to the fixture's length.
    let at = document
        .find("<MSM>")
        .expect("the fixture has an MSM element");
    let cut = &document.as_bytes()[..at];
    let parsed = parse(cut).expect("a profile from the prefix");
    assert_eq!(parsed.profile_name, "Coffee Shop Guest");
    assert!(
        parsed.authentication.is_none(),
        "the security is past the cut"
    );
    // A pull parser reaches the end of a truncated document without raising an
    // error, so the missing half is detected by the document ending inside an
    // element rather than by an XML failure.
    assert_eq!(parsed.ended_inside, vec!["WLANProfile"]);
    let shortfalls = parsed.shortfalls();
    let (reason, detail) = shortfalls
        .iter()
        .find(|(_, d)| d.contains("PREFIX"))
        .expect("the record says the file is a prefix");
    assert_eq!(*reason, IncompleteReason::ShortRead);
    assert!(detail.contains("WLANProfile"), "{detail}");
    assert_eq!(parsed.to_json()["whole_document"], serde_json::json!(false));
}

/// Bytes that are not a profile yield nothing at all.
#[test]
fn a_document_with_no_name_and_no_ssid_is_refused() {
    assert!(parse(b"").is_none());
    assert!(parse(
        br#"<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
            </WLANProfile>"#
    )
    .is_none());
}

/// An element carrying a namespace prefix is the same element: a document that
/// has been through other tooling must read the same as the service's own.
#[test]
fn a_prefixed_document_reads_the_same_as_an_unprefixed_one() {
    let document = r#"<?xml version="1.0"?>
<wlan:WLANProfile xmlns:wlan="http://www.microsoft.com/networking/WLAN/profile/v1">
  <wlan:name>Prefixed</wlan:name>
  <wlan:SSIDConfig><wlan:SSID><wlan:name>Prefixed</wlan:name></wlan:SSID></wlan:SSIDConfig>
  <wlan:connectionMode>manual</wlan:connectionMode>
</wlan:WLANProfile>"#;
    let parsed = parse(document.as_bytes()).expect("a profile");
    assert_eq!(parsed.profile_name, "Prefixed");
    assert_eq!(parsed.ssid_name.as_deref(), Some("Prefixed"));
    assert!(!parsed.connects_automatically());
}

/// A document with more elements than this build walks stops and says so,
/// rather than reading for as long as the file cares to go on.
#[test]
fn a_document_past_the_element_ceiling_stops_and_says_so() {
    let mut document = String::from(
        r#"<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
        <name>Padded</name>"#,
    );
    for n in 0..12_000 {
        document.push_str(&format!("<pad{n}>x</pad{n}>"));
    }
    document.push_str("</WLANProfile>");
    let parsed = parse(document.as_bytes()).expect("a profile");
    assert!(parsed.stopped_early);
    assert!(parsed
        .shortfalls()
        .iter()
        .any(|(reason, _)| *reason == IncompleteReason::CapReached));
}

/// **"Did not say" is not "said false".** A document with `keyMaterial` and no
/// `<protected>` element — another tool's element order, or a file cut before
/// that element — had its material published as a passphrase, with a sentence
/// asserting that `protected` is false. On a protected profile that would put
/// a DPAPI blob's hex on the record as the network's key, which is the one
/// field an examiner opens this file for.
#[test]
fn a_document_that_does_not_say_whether_its_key_is_protected_publishes_no_key() {
    let hex = blob_hex();
    let document = protected_profile(&hex).replace("<protected>true</protected>\n\t\t\t\t", "");
    assert!(
        !document.contains("<protected>"),
        "the fixture has no protected element"
    );
    let parsed = parse(document.as_bytes()).expect("a profile");
    match parsed.key.as_ref().expect("a key state") {
        Key::ProtectedNotStated {
            material_looks_like_dpapi,
            blob,
            characters,
            ..
        } => {
            assert!(
                material_looks_like_dpapi,
                "the material is a DPAPI blob and is recognised as one"
            );
            assert_eq!(*characters, hex.chars().count());
            assert_eq!(
                blob.as_ref().map(|b| b.master_key_guid.clone()),
                Some(crate::dpapi::test_support::MASTER_KEY.to_string()),
                "naming the master key is useful whatever the document failed to say"
            );
        }
        other => panic!("{other:?}"),
    }
    let json = parsed.to_json();
    assert_eq!(json["key_state"], "protection_not_stated");
    assert!(
        json["key"].is_null(),
        "no key is published: {}",
        json["key"]
    );
    let statement = json["key_statement"].as_str().expect("a statement");
    assert!(statement.contains("DOES NOT SAY"), "{statement}");
    assert!(statement.contains("ARE a DPAPI blob"), "{statement}");
    assert!(
        !statement.contains("IN PLAIN TEXT"),
        "and it is not called a cleartext key: {statement}"
    );
    let (reason, detail) = parsed
        .shortfalls()
        .into_iter()
        .find(|(_, d)| d.contains("does not say whether the key is protected"))
        .expect("the record is short of the document's own statement");
    assert_eq!(reason, IncompleteReason::UnresolvedStructure);
    assert!(detail.contains("IS a DPAPI blob"), "{detail}");

    // The same with material that is not a blob: still not published as a key,
    // and the sentence says which of the two it could be.
    let document =
        protected_profile("hunter2").replace("<protected>true</protected>\n\t\t\t\t", "");
    let parsed = parse(document.as_bytes()).expect("a profile");
    match parsed.key.as_ref().expect("a key state") {
        Key::ProtectedNotStated {
            material_looks_like_dpapi,
            blob,
            ..
        } => {
            assert!(!material_looks_like_dpapi);
            assert!(blob.is_none());
        }
        other => panic!("{other:?}"),
    }
    let json = parsed.to_json();
    assert!(json["key"].is_null());
    assert!(json["key_statement"]
        .as_str()
        .is_some_and(|s| s.contains("may be a passphrase in the clear")));

    // And a document that DOES say false is still a key in the clear: the two
    // states are not folded together.
    let document = protected_profile("hunter2").replace(
        "<protected>true</protected>",
        "<protected>false</protected>",
    );
    let parsed = parse(document.as_bytes()).expect("a profile");
    assert_eq!(parsed.to_json()["key"], "hunter2");
    assert_eq!(parsed.to_json()["key_state"], "in_the_clear");
}
