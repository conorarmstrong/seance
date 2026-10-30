//! One WLAN profile document, read.
//!
//! # The schema
//!
//! ```xml
//! <WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
//!   <name>Airport Free WiFi</name>
//!   <SSIDConfig>
//!     <SSID><hex>41697270...</hex><name>Airport Free WiFi</name></SSID>
//!     <nonBroadcast>true</nonBroadcast>
//!   </SSIDConfig>
//!   <connectionType>ESS</connectionType>
//!   <connectionMode>auto</connectionMode>
//!   <MSM><security>
//!     <authEncryption>
//!       <authentication>WPA2PSK</authentication>
//!       <encryption>AES</encryption>
//!       <useOneX>false</useOneX>
//!     </authEncryption>
//!     <sharedKey>
//!       <keyType>passPhrase</keyType>
//!       <protected>true</protected>
//!       <keyMaterial>01000000D08C9DDF...</keyMaterial>
//!     </sharedKey>
//!   </security></MSM>
//! </WLANProfile>
//! ```
//!
//! # Read by element name, not by position
//!
//! The service writes the elements in a fixed order and other tooling does
//! not, so this walks the document and keys off the element names it knows.
//! An element it does not know is counted, not ignored: a profile carrying
//! something this build cannot read must not present as one that was read in
//! full.
//!
//! # The SSID is two claims, and they can disagree
//!
//! `<hex>` is the SSID as bytes, `<name>` is the same thing as text — and an
//! SSID is a byte string that need not be valid UTF-8, so the hex is the
//! authoritative one. Where both are present and disagree, both are reported
//! and the disagreement is on the record, because an SSID crafted to render as
//! one network and resolve as another is exactly the trick that would exploit
//! a parser that quietly preferred the text.

use quick_xml::events::Event;
use quick_xml::Reader;
use seance_core::io::IncompleteReason;
use serde_json::json;

/// Elements this build will walk in one document.
const MAX_ELEMENTS: usize = 10_000;

/// Characters of one text node kept.
const MAX_TEXT_CHARS: usize = 4096;

/// The sentence every profile record carries.
pub const STATEMENT: &str = concat!(
    "A configured wireless network, read from the profile the WLAN service wrote. It states ",
    "that this machine was SET UP to join this network -- and, where connects_automatically is ",
    "true, that it would join whenever in range. It does NOT state when it joined, or that it ",
    "ever did: the profile carries no timestamps at all, and the join history is in the ",
    "Microsoft-Windows-WLAN-AutoConfig/Operational event channel and the NetworkList registry ",
    "keys, which this module does not read."
);

/// Whether these bytes begin a WLAN profile document.
///
/// By the root element and its namespace, both of which Windows always
/// writes. An XML file that merely mentions the word is not one.
pub fn looks_like_profile(head: &[u8]) -> bool {
    let text = String::from_utf8_lossy(head);
    text.contains("<WLANProfile")
        && text.contains("://www.microsoft.com/networking/WLAN/profile/v1")
}

/// How a profile's key reached the disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Key {
    /// The profile has no `sharedKey` at all: an open network, or one whose
    /// authentication is 802.1X and whose credential is elsewhere.
    None,
    /// `protected` was `false`: the passphrase is in the file, in the clear.
    /// This is what `netsh wlan export profile key=clear` writes, and what
    /// some deployment tooling leaves behind.
    Clear { key_type: String, key: String },
    /// `protected` was `true` and the material is a DPAPI blob this build
    /// recognised.
    Dpapi {
        key_type: String,
        blob: crate::dpapi::Blob,
    },
    /// `protected` was `true` and the material is not a blob this build can
    /// read. Counted rather than presented as absent.
    ProtectedUnreadable { key_type: String, detail: String },
    /// There is `keyMaterial` and **the document never said whether it is
    /// protected**. "Did not say" is not "said false": a document in another
    /// tool's element order, or one cut before `<protected>`, would otherwise
    /// have a DPAPI blob's hex published as a passphrase — on the field an
    /// examiner opens the file for. What the material looks like is reported
    /// (a DPAPI blob is recognisable by its own first twenty bytes) and it is
    /// never called a key in the clear.
    ProtectedNotStated {
        key_type: String,
        material_looks_like_dpapi: bool,
        /// The blob's fields where it is one: naming the master key is useful
        /// whatever the document failed to say.
        blob: Option<crate::dpapi::Blob>,
        characters: usize,
    },
}

impl Key {
    pub fn as_str(&self) -> &'static str {
        match self {
            Key::None => "none",
            Key::Clear { .. } => "in_the_clear",
            Key::Dpapi { .. } => "dpapi_protected",
            Key::ProtectedUnreadable { .. } => "protected_unreadable",
            Key::ProtectedNotStated { .. } => "protection_not_stated",
        }
    }
}

/// One profile document's fields.
#[derive(Debug, Clone, Default)]
pub struct Profile {
    pub profile_name: String,
    /// The SSID as text, where the document gave one.
    pub ssid_name: Option<String>,
    /// The SSID as bytes, where the document gave the hex form.
    pub ssid_hex: Option<String>,
    /// The hex form rendered as text, where it is valid UTF-8.
    pub ssid_from_hex: Option<String>,
    /// Whether the two forms disagree, which is a finding rather than a
    /// detail.
    pub ssid_forms_disagree: bool,
    /// `nonBroadcast`: the network does not announce itself, so a machine
    /// configured for it actively looks for it.
    pub hidden: Option<bool>,
    pub connection_type: Option<String>,
    pub connection_mode: Option<String>,
    pub authentication: Option<String>,
    pub encryption: Option<String>,
    pub uses_8021x: Option<bool>,
    pub mac_randomisation: Option<bool>,
    pub key: Option<Key>,
    /// Elements this build does not read, by name and count.
    pub unread_elements: std::collections::BTreeMap<String, usize>,
    /// Whether the walk ended before the document did.
    pub stopped_early: bool,
    /// Whether the XML itself failed part way through.
    pub xml_error: Option<String>,
    /// The elements the document was still inside when it ended, outermost
    /// first. A non-empty list means the file is a PREFIX of a profile: a
    /// pull parser reaches the end of a truncated document without an error,
    /// so without this a file cut in half reads as one that simply had fewer
    /// fields.
    pub ended_inside: Vec<String>,
    /// The three `sharedKey` children as they are seen. Private, and resolved
    /// into [`Profile::key`] once the document ends, so a document listing
    /// `keyMaterial` before `protected` reads the same as one that does not.
    key_parts: KeyParts,
}

impl Profile {
    /// The SSID to file this network under: the hex form where it renders,
    /// because it is the authoritative one, and the text form otherwise.
    pub fn ssid(&self) -> String {
        self.ssid_from_hex
            .clone()
            .or_else(|| self.ssid_name.clone())
            .unwrap_or_else(|| self.profile_name.clone())
    }

    /// Whether the network needs no credential at all — the finding an
    /// examiner reads first, because it is how a machine ends up on a network
    /// nobody controls.
    pub fn is_open(&self) -> bool {
        let authentication = self
            .authentication
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase();
        // An absent encryption element is not a statement that there is none,
        // but an `open` authentication with nothing else said is as close as
        // the document comes; `none` says it outright.
        let encryption = self
            .encryption
            .as_deref()
            .unwrap_or("none")
            .to_ascii_lowercase();
        authentication == "open" && encryption == "none"
    }

    pub fn connects_automatically(&self) -> bool {
        self.connection_mode
            .as_deref()
            .is_some_and(|m| m.eq_ignore_ascii_case("auto"))
    }

    pub fn short_desc(&self) -> String {
        let security = match (&self.authentication, &self.encryption) {
            (Some(a), Some(e)) => format!("{a}/{e}"),
            (Some(a), None) => a.clone(),
            _ => "security not stated".to_string(),
        };
        format!("{} ({security})", self.ssid())
    }

    /// Every reason this record is short of the document.
    pub fn shortfalls(&self) -> Vec<(IncompleteReason, String)> {
        let mut out = Vec::new();
        if let Some(error) = &self.xml_error {
            out.push((
                IncompleteReason::UnresolvedStructure,
                format!(
                    "the document's XML failed part way through ({error}); the fields read \
                     before the failure are here and anything after it is not"
                ),
            ));
        }
        if !self.ended_inside.is_empty() {
            out.push((
                IncompleteReason::ShortRead,
                format!(
                    "the document ends while still inside <{}>: this file is a PREFIX of a \
                     profile, not a whole one, and any field after the cut is missing rather \
                     than absent",
                    self.ended_inside.join("><")
                ),
            ));
        }
        if self.stopped_early {
            out.push((
                IncompleteReason::CapReached,
                format!(
                    "the walk stopped at this build's ceiling of {MAX_ELEMENTS} elements; \
                     anything after that point was not read"
                ),
            ));
        }
        if !self.unread_elements.is_empty() {
            let listed: Vec<String> = self
                .unread_elements
                .iter()
                .map(|(name, count)| format!("{name} ({count})"))
                .collect();
            out.push((
                IncompleteReason::Unmapped,
                format!(
                    "this profile carries {} element(s) this build does not read: {}. They are \
                     in the file and not in this record",
                    self.unread_elements.len(),
                    listed.join(", ")
                ),
            ));
        }
        match &self.key {
            Some(Key::Dpapi { blob, .. }) => {
                out.push((IncompleteReason::Encrypted, blob.statement()))
            }
            Some(Key::ProtectedUnreadable { detail, .. }) => {
                out.push((IncompleteReason::Encrypted, detail.clone()))
            }
            Some(Key::ProtectedNotStated {
                material_looks_like_dpapi,
                characters,
                ..
            }) => out.push((
                // Not `Encrypted`: what this record is short by is the
                // document's own statement about its key, which is a
                // structure this build could not resolve.
                IncompleteReason::UnresolvedStructure,
                format!(
                    "this profile carries {characters} characters of keyMaterial and NO \
                     `protected` element, so the document does not say whether the key is \
                     protected. The material {} a DPAPI blob. The key is not published \
                     either way",
                    if *material_looks_like_dpapi {
                        "IS"
                    } else {
                        "is not"
                    }
                ),
            )),
            _ => {}
        }
        if self.ssid_forms_disagree {
            out.push((
                IncompleteReason::UnresolvedStructure,
                "the SSID's two forms disagree: <hex> and <name> in this document are not the \
                 same string. The hex is the authoritative one -- an SSID is a byte string, not \
                 text -- and both are on this record because a profile whose name renders as \
                 one network and resolves as another is a thing somebody built on purpose."
                    .to_string(),
            ));
        }
        out
    }

    pub fn to_json(&self) -> serde_json::Value {
        let key = self.key.clone().unwrap_or(Key::None);
        json!({
            "ssid_name": self.ssid_name,
            "ssid_hex": self.ssid_hex,
            "ssid_from_hex": self.ssid_from_hex,
            "ssid_forms_disagree": self.ssid_forms_disagree,
            "hidden_network": self.hidden,
            "connection_type": self.connection_type,
            "connection_mode": self.connection_mode,
            "connects_automatically": self.connects_automatically(),
            "authentication": self.authentication,
            "encryption": self.encryption,
            "security_types": security_types(self),
            "open_network": self.is_open(),
            "uses_8021x": self.uses_8021x,
            "mac_randomisation": self.mac_randomisation,
            "key_state": key.as_str(),
            "key_type": match &key {
                Key::Clear { key_type, .. }
                | Key::Dpapi { key_type, .. }
                | Key::ProtectedUnreadable { key_type, .. }
                | Key::ProtectedNotStated { key_type, .. } => Some(key_type.clone()),
                Key::None => None,
            },
            // The passphrase, where the file holds it in the clear. It is the
            // reason an examiner opens this file, and a record that withheld
            // what the evidence states would be the wrong kind of caution.
            "key": match &key {
                Key::Clear { key, .. } => Some(key.clone()),
                _ => None,
            },
            "key_dpapi": match &key {
                Key::Dpapi { blob, .. } => Some(blob.to_json()),
                // Naming the master key is useful whatever the document
                // failed to say about protection.
                Key::ProtectedNotStated { blob: Some(blob), .. } => Some(blob.to_json()),
                _ => None,
            },
            "key_statement": match &key {
                Key::None =>
                    "This profile carries no pre-shared key. An open network needs none; a \
                     profile using 802.1X keeps its credential elsewhere."
                        .to_string(),
                Key::Clear { .. } =>
                    "The pre-shared key is IN THIS FILE IN PLAIN TEXT: the profile's \
                     `protected` element is false, which is what an export with `key=clear` \
                     and some deployment tooling writes. The value in `key` is what the file \
                     states."
                        .to_string(),
                Key::Dpapi { blob, .. } => blob.statement(),
                Key::ProtectedUnreadable { detail, .. } => detail.clone(),
                Key::ProtectedNotStated {
                    material_looks_like_dpapi,
                    blob,
                    characters,
                    ..
                } => {
                    if *material_looks_like_dpapi {
                        format!(
                            "THIS DOCUMENT DOES NOT SAY whether its key is protected -- it has no `protected` element -- and the {characters} characters of keyMaterial it carries ARE a DPAPI blob, so the key is NOT in the clear and is not in this record.{}",
                            blob.as_ref()
                                .map(|b| format!(" {}", b.statement()))
                                .unwrap_or_default()
                        )
                    } else {
                        format!(
                            "THIS DOCUMENT DOES NOT SAY whether its key is protected -- it has no `protected` element. The {characters} characters of keyMaterial it carries are not a DPAPI blob this build recognises, so they may be a passphrase in the clear or a protected form this build does not know. They are NOT published as a key: a value presented as a passphrase that is not one is worse than no value, and the material is in the file."
                        )
                    }
                }
            },
            "ended_inside": self.ended_inside,
            "whole_document": self.ended_inside.is_empty() && self.xml_error.is_none()
                && !self.stopped_early,
            "unread_elements": self.unread_elements.iter()
                .map(|(k, v)| (k.clone(), json!(v)))
                .collect::<serde_json::Map<_, _>>(),
            "join_times_available": false,
            "join_times_note":
                "This profile carries NO timestamps: it states that the machine was \
                 CONFIGURED to join this network, not that it ever did. When it actually \
                 joined is read separately -- from the NetworkList registry keys (a \
                 NetworkProfile record, whose local times carry a measured zone offset) and \
                 from the Microsoft-Windows-WLAN-AutoConfig/Operational channel, whose four \
                 events keep an attempt apart from a connection.",
        })
    }
}

/// Read a profile document, or refuse it.
///
/// `None` only where the document yields neither a profile name nor an SSID:
/// everything else is reported with what was read and a statement of what was
/// not, because a profile that is half-readable still names a network.
pub fn parse(bytes: &[u8]) -> Option<Profile> {
    let text = String::from_utf8_lossy(bytes);
    let mut reader = Reader::from_str(&text);
    reader.trim_text(true);
    let mut out = Profile::default();
    let mut path: Vec<String> = Vec::new();
    let mut elements = 0usize;
    // Which text node the reader is inside, as the path to it. Keyed off the
    // path rather than the element name alone: <name> appears twice in this
    // schema, once as the profile's and once as the SSID's, and reading them
    // as the same field would file every network under the wrong SSID.
    loop {
        match reader.read_event() {
            Ok(Event::Eof) => {
                // Still inside an element: the document ended before it did.
                if !path.is_empty() {
                    out.ended_inside = path.clone();
                }
                break;
            }
            Ok(Event::Start(element)) => {
                elements += 1;
                if elements > MAX_ELEMENTS {
                    out.stopped_early = true;
                    break;
                }
                path.push(local_name(element.name().as_ref()));
            }
            Ok(Event::End(_)) => {
                path.pop();
            }
            Ok(Event::Empty(element)) => {
                elements += 1;
                if elements > MAX_ELEMENTS {
                    out.stopped_early = true;
                    break;
                }
                // An empty element states that the field is present and empty,
                // which for this schema carries no value to read.
                let name = local_name(element.name().as_ref());
                if !KNOWN.contains(&name.as_str()) {
                    *out.unread_elements.entry(name).or_insert(0) += 1;
                }
            }
            Ok(Event::Text(text)) => {
                let value = text
                    .unescape()
                    .map(|c| c.chars().take(MAX_TEXT_CHARS).collect::<String>())
                    .unwrap_or_default();
                if value.is_empty() {
                    continue;
                }
                assign(&mut out, &path, &value);
            }
            Ok(_) => {}
            Err(error) => {
                out.xml_error = Some(error.to_string());
                break;
            }
        }
    }
    finish(&mut out);
    (!out.profile_name.is_empty() || out.ssid_name.is_some() || out.ssid_hex.is_some())
        .then_some(out)
}

/// The element names this build reads. Anything else is counted as unread, so
/// a profile carrying something new says so.
const KNOWN: &[&str] = &[
    "WLANProfile",
    "name",
    "SSIDConfig",
    "SSID",
    "hex",
    "nonBroadcast",
    "connectionType",
    "connectionMode",
    "MSM",
    "security",
    "authEncryption",
    "authentication",
    "encryption",
    "useOneX",
    "sharedKey",
    "keyType",
    "protected",
    "keyMaterial",
    "MacRandomization",
    "enableRandomization",
];

/// One text node, filed by the path it sits at.
fn assign(out: &mut Profile, path: &[String], value: &str) {
    let here = path.last().map(String::as_str).unwrap_or("");
    let parent = path
        .len()
        .checked_sub(2)
        .and_then(|i| path.get(i))
        .map(String::as_str)
        .unwrap_or("");
    match (parent, here) {
        ("WLANProfile", "name") => out.profile_name = value.to_string(),
        ("SSID", "name") => out.ssid_name = Some(value.to_string()),
        ("SSID", "hex") => out.ssid_hex = Some(value.to_string()),
        ("SSIDConfig", "nonBroadcast") => out.hidden = Some(is_true(value)),
        ("WLANProfile", "connectionType") => out.connection_type = Some(value.to_string()),
        ("WLANProfile", "connectionMode") => out.connection_mode = Some(value.to_string()),
        ("authEncryption", "authentication") => out.authentication = Some(value.to_string()),
        ("authEncryption", "encryption") => out.encryption = Some(value.to_string()),
        ("authEncryption", "useOneX") => out.uses_8021x = Some(is_true(value)),
        ("MacRandomization", "enableRandomization") => out.mac_randomisation = Some(is_true(value)),
        ("sharedKey", "keyType") => out.key_parts.key_type = Some(value.to_string()),
        ("sharedKey", "protected") => out.key_parts.protected = Some(is_true(value)),
        ("sharedKey", "keyMaterial") => out.key_parts.material = Some(value.to_string()),
        _ => {
            if !KNOWN.contains(&here) {
                *out.unread_elements.entry(here.to_string()).or_insert(0) += 1;
            }
        }
    }
}

/// The authentication and encryption as one list, for the field the macOS
/// sibling emits under the same name.
fn security_types(profile: &Profile) -> Vec<String> {
    [profile.authentication.clone(), profile.encryption.clone()]
        .into_iter()
        .flatten()
        .collect()
}

/// `true`, `1` — the two forms this schema uses for a boolean.
fn is_true(value: &str) -> bool {
    matches!(value.trim().to_ascii_lowercase().as_str(), "true" | "1")
}

/// The three `sharedKey` children, which arrive in any order.
#[derive(Debug, Clone, Default)]
struct KeyParts {
    key_type: Option<String>,
    protected: Option<bool>,
    material: Option<String>,
}

/// Resolve the SSID's two forms and the key once the whole document has been
/// seen.
fn finish(out: &mut Profile) {
    if let Some(hex) = &out.ssid_hex {
        if let Some(bytes) = crate::dpapi::from_hex(hex) {
            if let Ok(text) = String::from_utf8(bytes) {
                out.ssid_from_hex = Some(text);
            }
        }
    }
    if let (Some(from_hex), Some(name)) = (&out.ssid_from_hex, &out.ssid_name) {
        out.ssid_forms_disagree = from_hex != name;
    }
    let parts = std::mem::take(&mut out.key_parts);
    let key_type = parts
        .key_type
        .clone()
        .unwrap_or_else(|| "(not stated)".into());
    out.key = match (parts.protected, parts.material) {
        (_, None) => Some(Key::None),
        (Some(false), Some(material)) => Some(Key::Clear {
            key_type,
            key: material,
        }),
        // The document never said. That is its own state: publishing the
        // material as a passphrase would put a DPAPI blob's hex on the record
        // as this network's key, and saying `protected` is false would assert
        // the value of an element that is not in the file.
        (None, Some(material)) => {
            let blob = crate::dpapi::from_hex(&material).and_then(|b| crate::dpapi::parse(&b));
            let looks_like_dpapi = blob.is_some()
                || crate::dpapi::from_hex(&material)
                    .is_some_and(|b| crate::dpapi::looks_like_dpapi(&b));
            Some(Key::ProtectedNotStated {
                key_type,
                material_looks_like_dpapi: looks_like_dpapi,
                blob,
                characters: material.chars().count(),
            })
        }
        (Some(true), Some(material)) => {
            match crate::dpapi::from_hex(&material).and_then(|b| crate::dpapi::parse(&b)) {
                Some(blob) => Some(Key::Dpapi { key_type, blob }),
                None => Some(Key::ProtectedUnreadable {
                    key_type,
                    detail: format!(
                        "the profile says its key is protected and the material ({} \
                         characters) is not a DPAPI blob this build can read; the key is not in \
                         this record and the material is in the file",
                        material.chars().count()
                    ),
                }),
            }
        }
    };
}

/// An element's name without its namespace prefix. Windows writes the
/// namespace as the default one, but a document that has been through other
/// tooling may carry a prefix, and `wlan:name` is the same element as `name`.
fn local_name(raw: &[u8]) -> String {
    let text = String::from_utf8_lossy(raw);
    text.rsplit(':').next().unwrap_or(&text).to_string()
}

#[cfg(test)]
#[path = "profile_tests.rs"]
mod profile_tests;
