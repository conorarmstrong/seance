//! Raw value capture for the registry-resident artifacts (`ROADMAP` §2.5).
//!
//! # Why the walk's own output will not do
//!
//! `all_values` publishes a **rendering**: a binary value under 64 bytes
//! becomes space-separated hex, over 64 bytes it becomes
//! `"72 bytes (binary data)"` plus base64. A UserAssist entry is 72 bytes and a
//! BAM entry is 24, so decoding either from `all_values` would be a decoder
//! taking a hidden dependency on a display format — one reformat away from
//! silently reading nothing.
//!
//! So the walk hands the bytes over directly, for the keys that need them and
//! no others.
//!
//! # Why the capture is targeted
//!
//! An unanchored hive captures nothing. `SOFTWARE` holds 117,488 keys and
//! several hundred megabytes of value data; capturing all of it to decode a few
//! hundred UserAssist entries would trade a real memory ceiling for a
//! convenience, and `HUNT-125` is this project already OOM-killed by ingest
//! memory that scaled with the evidence.
//!
//! # And it is bounded, and says when the bound was reached
//!
//! `MAX_RESIDENT_VALUES` and `MAX_RESIDENT_BYTES` cap it. A cap that stopped
//! the capture is stamped onto the hive record: a record list that stopped at a
//! ceiling and reads as complete is the failure this codebase is written
//! against.

use seance_hive::KeyValueDataType;

/// Values captured before the collector stops.
///
/// Reached only by a hive far outside anything in the corpus: the largest real
/// anchored population is a `MUICache` with 131 values and a `Count` key with
/// 56.
pub const MAX_RESIDENT_VALUES: usize = 200_000;

/// Bytes captured before the collector stops.
pub const MAX_RESIDENT_BYTES: usize = 8 * 1024 * 1024;

/// Which registry-resident family a key belongs to.
///
/// Classified by path, once per key, so the value loop can ask a cheap question
/// instead of matching strings per value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Anchor {
    /// `…\Explorer\UserAssist\{GUID}` — holds only `Version`.
    UserAssistGuid { guid: String },
    /// `…\Explorer\UserAssist\{GUID}\Count` — holds the entries.
    UserAssistCount { guid: String },
    /// `…\ControlSet00N\Services\{bam,dam}\…\UserSettings\<SID>`, in either
    /// of the two layouts Windows 10 has used.
    BamSid { key: crate::bam::BamSidKey },
    /// `…\ShellNoRoam\MUICache` or `…\Shell\MuiCache` — the display names
    /// the shell cached.
    MuiCache { form: crate::muicache::SourceForm },
    /// One of the shell's most-recently-used lists.
    Mru { kind: crate::mru::MruKind },
    /// `Services\WSearch` — whether the indexer was configured to run (§2.6).
    WindowsSearchService { control_set: String },
    /// `SOFTWARE\Microsoft\Windows Search` — setup state and index location.
    WindowsSearchSoftware,
    /// The `MountedDevices` key: which drive letter a device was mounted at
    /// (§2.6). Captured as bytes because both of its value shapes are
    /// `REG_BINARY` -- one a UTF-16 path, one a signature and an offset.
    MountedDevices,
    /// `…\NetworkList\Profiles\{GUID}` — a network this machine has been on,
    /// with the times it was first and last on it (§4.3). Captured as bytes
    /// because `DateCreated` and `DateLastConnected` are 16-byte
    /// `REG_BINARY` SYSTEMTIMEs, and a date decoded from `all_values`' hex
    /// rendering would be a decoder depending on a display format.
    NetworkListProfile { guid: String },
    /// `…\NetworkList\Signatures\{Managed,Unmanaged}\<sig>` — what the
    /// machine recognised a network by: the SSID, the DNS suffix and the
    /// default gateway's MAC (§4.3).
    NetworkListSignature { managed: bool, signature: String },
    /// A `Tcpip\Parameters\Interfaces\{GUID}` key (§2.6).
    NetworkInterface { control_set: String, guid: String },
    /// A device-property leaf key, whose raw bytes carry an install or
    /// connection time (§2.6). Captured as bytes because `all_values` renders
    /// an 8-byte REG_BINARY to hex, and a FILETIME decoded from a hex string
    /// is a decoder depending on a display format.
    DeviceProperty { key: crate::devprops::PropertyKey },
    /// An outgoing-RDP destination key.
    Rdp { kind: crate::mru::RdpKeyKind },
    /// `SAM\Domains\Account\Users\<8 hex>` — the account's `F` and `V`
    /// values (§2.6). Captured as bytes because `F` is an 80-byte fixed record
    /// and `V` a descriptor array, and `all_values` renders either to a hex
    /// string or, over 64 bytes, to a byte count and base64.
    SamUser { rid_hex: String },
    /// `SAM\Domains\Account\Users\Names\<name>` — the name index. Its
    /// default value carries the RID in its **type** field with zero bytes of
    /// data, so the join needs the type and not the data.
    SamUserName { name: String },
    /// The BAM/DAM container key, whose mere existence distinguishes "this
    /// hive predates BAM" from "BAM exists and recorded nothing".
    BamService {
        service: String,
        control_set: String,
        /// Whether this is the `UserSettings` container rather than the
        /// service key or its `State` parent.
        is_usersettings: bool,
    },
}

/// Classify a key path into an anchor.
///
/// Matched case-insensitively on path **segments**, because a hive holds either
/// casing and a substring match would catch a key merely named like one. The
/// walk's own root segment (`ROOT`, or `CMI-CreateHive{…}`) is ignored, exactly
/// as `installed::rootless_key` does.
pub fn anchor_of(key_path: &str) -> Option<Anchor> {
    // BAM/DAM first: it recognises its own path shape, including both of the
    // two layouts Windows 10 has used for it.
    if let Some(key) = crate::bam::bam_sid_key(key_path) {
        return Some(Anchor::BamSid { key });
    }
    if let Some(form) = crate::muicache::muicache_key(key_path) {
        return Some(Anchor::MuiCache { form });
    }
    if let Some(kind) = crate::mru::mru_kind_of(key_path) {
        return Some(Anchor::Mru { kind });
    }
    if let Some(key) = crate::devprops::property_key(key_path) {
        return Some(Anchor::DeviceProperty { key });
    }
    if let Some(control_set) = crate::winsearch::wsearch_service_key(key_path) {
        return Some(Anchor::WindowsSearchService { control_set });
    }
    if crate::winsearch::wsearch_software_key(key_path) {
        return Some(Anchor::WindowsSearchSoftware);
    }
    if crate::mounted::is_mounted_devices_key(key_path) {
        return Some(Anchor::MountedDevices);
    }
    if let Some((control_set, guid)) = crate::netinterfaces::interface_key(key_path) {
        return Some(Anchor::NetworkInterface { control_set, guid });
    }
    if let Some(guid) = crate::networklist::profile_key(key_path) {
        return Some(Anchor::NetworkListProfile { guid });
    }
    if let Some((managed, signature)) = crate::networklist::signature_key(key_path) {
        return Some(Anchor::NetworkListSignature { managed, signature });
    }
    if let Some(rid_hex) = crate::sam::sam_account_key(key_path) {
        return Some(Anchor::SamUser { rid_hex });
    }
    if let Some(name) = crate::sam::sam_name_key(key_path) {
        return Some(Anchor::SamUserName { name });
    }
    if let Some(kind) = crate::mru::rdp_key(key_path) {
        return Some(Anchor::Rdp { kind });
    }
    if let Some((service, control_set, is_usersettings)) = crate::bam::bam_service_key(key_path) {
        return Some(Anchor::BamService {
            service,
            control_set,
            is_usersettings,
        });
    }
    let segments: Vec<&str> = key_path
        .split('\\')
        .filter(|s| !s.is_empty())
        .skip(1) // the walk's synthetic root
        .collect();
    let lower: Vec<String> = segments.iter().map(|s| s.to_ascii_lowercase()).collect();

    // `…\Explorer\UserAssist\{GUID}` and `…\{GUID}\Count`.
    let ua = lower.iter().position(|s| s == "userassist")?;
    let guid_at = ua + 1;
    let guid = segments.get(guid_at)?;
    // A GUID, not any subkey: the key Windows writes is brace-delimited, and a
    // matcher that accepted anything here would classify unrelated subkeys.
    if !(guid.starts_with('{') && guid.ends_with('}')) {
        return None;
    }
    match lower.len() - guid_at {
        1 => Some(Anchor::UserAssistGuid {
            guid: guid.to_string(),
        }),
        2 if lower[guid_at + 1] == "count" => Some(Anchor::UserAssistCount {
            guid: guid.to_string(),
        }),
        _ => None,
    }
}

/// One value's bytes, as the hive holds them.
#[derive(Clone, Debug)]
pub struct ResidentValue {
    pub name: String,
    pub data_type: Option<KeyValueDataType>,
    pub data: Vec<u8>,
}

/// One anchored key and the values captured from it.
#[derive(Clone, Debug)]
pub struct ResidentKey {
    pub key_path: String,
    pub anchor: Anchor,
    pub last_written_filetime: u64,
    pub values: Vec<ResidentValue>,
}

/// The capture, and whether it is complete.
#[derive(Clone, Debug, Default)]
pub struct ResidentCapture {
    pub keys: Vec<ResidentKey>,
    values: usize,
    bytes: usize,
    /// Set when a cap stopped the capture. Never silent.
    pub capped: Option<&'static str>,
}

impl ResidentCapture {
    /// Begin capturing an anchored key. Returns the index to push values into,
    /// or `None` when a cap has already been reached.
    pub fn begin_key(
        &mut self,
        key_path: &str,
        anchor: Anchor,
        last_written_filetime: u64,
    ) -> Option<usize> {
        if self.capped.is_some() {
            return None;
        }
        self.keys.push(ResidentKey {
            key_path: key_path.to_string(),
            anchor,
            last_written_filetime,
            values: Vec::new(),
        });
        Some(self.keys.len() - 1)
    }

    /// Capture one value's bytes against the key at `index`.
    pub fn push_value(
        &mut self,
        index: usize,
        name: &str,
        data_type: Option<KeyValueDataType>,
        data: &[u8],
    ) {
        if self.capped.is_some() {
            return;
        }
        if self.values >= MAX_RESIDENT_VALUES {
            self.capped = Some("the registry-resident value cap was reached");
            return;
        }
        if self.bytes + data.len() > MAX_RESIDENT_BYTES {
            self.capped = Some("the registry-resident byte cap was reached");
            return;
        }
        if let Some(key) = self.keys.get_mut(index) {
            self.values += 1;
            self.bytes += data.len();
            key.values.push(ResidentValue {
                name: name.to_string(),
                data_type,
                data: data.to_vec(),
            });
        }
    }

    /// Whether every anchored value was captured.
    pub fn complete(&self) -> bool {
        self.capped.is_none()
    }

    /// Keys of one anchor family.
    pub fn keys_matching<'a, F>(&'a self, f: F) -> impl Iterator<Item = &'a ResidentKey>
    where
        F: Fn(&Anchor) -> bool + 'a,
    {
        self.keys.iter().filter(move |k| f(&k.anchor))
    }
}
