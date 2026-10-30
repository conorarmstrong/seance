//! The shell's most-recently-used lists, and outgoing RDP destinations.
//!
//! # What these are
//!
//! `RecentDocs`, `RunMRU`, `TypedPaths` and the four `ComDlg32` lists record
//! what a user opened, typed and saved through the shell — per user, in order,
//! and surviving the files themselves. `Terminal Server Client` records where
//! they tried to connect **from** this machine.
//!
//! `ROADMAP` §2.5.
//!
//! # Two ordering conventions, both real
//!
//! `MRUListEx` is `REG_BINARY`: little-endian `u32` indices, most-recent-first,
//! terminated by `0xFFFFFFFF`. `MRUList` is `REG_SZ` letters in order, and only
//! `RunMRU` uses it. Handling one would leave the other's entries unordered —
//! and an MRU list without its order is most of its value gone.
//!
//! # Two states a naive implementation gets wrong, both in real hives
//!
//! A value present but **not named** by `MRUListEx` is a stale entry left after
//! the list shrank: it has no position, and giving it one would assert an
//! ordering the hive does not record. An index naming a value that **does not
//! exist** is counted onto the key's coverage and stated — never silently
//! skipped, because the gap is a fact about the hive.
//!
//! # The shell item is read through the format, and the record says how far
//!
//! Most of these bodies are a UTF-16 display name, a NUL, then a shell item ID
//! list. `CIDSizeMRU` and `FirstFolder` are a name and no list: their trailing
//! bytes are kept and disclosed as undecoded, never walked (`HUNT-167`). The list is walked through `seance_shell_item` one item at a time:
//! each item's own name, the deepest item's FAT times, and (`HUNT-147`) the
//! deepest item's MFT file reference where a version-7+ `BEEF0004` block
//! carries one. `parsed` is **per item** — a type this build does not know, or
//! an instance too short for its fields, reports `false` for that item alone —
//! and the record counts how many items were not read. The bytes are always
//! published whole, so a later build can decode what this one could not.
//!
//! # And no entry has a time of its own
//!
//! The key's `nk` write time is the **key's**. One event per key, naming the
//! position-0 entry, is the only honest placement: an event per entry at the
//! key's time would date every entry to the most recent action.

use base64::Engine as _;
use seance_hive::KeyValueDataType;
use serde_json::{json, Value};

/// Which MRU family a key belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MruKind {
    /// `…\Explorer\RecentDocs`, and its per-extension subkeys.
    RecentDocs,
    /// `…\Explorer\RunMRU` — the Run dialog. The only `MRUList` user.
    RunMru,
    /// `…\Explorer\TypedPaths` — typed into Explorer's address bar.
    TypedPaths,
    /// `…\ComDlg32\OpenSavePidlMRU\<ext>` (XP: `OpenSaveMRU`).
    OpenSavePidlMru,
    /// `…\ComDlg32\LastVisitedPidlMRU` (XP: `LastVisitedMRU`).
    LastVisitedPidlMru,
    /// `…\ComDlg32\CIDSizeMRU`. A program's name — a string MRU, as plaso
    /// reads it — not a shell item (`HUNT-167`).
    CidSizeMru,
    /// `…\ComDlg32\FirstFolder`. A program's path, read the same way.
    FirstFolder,
    /// `…\Explorer\WordWheelQuery` — what was typed into Windows Explorer's
    /// search box, one UTF-16LE string per value (NIST CFReDS Data Leakage key
    /// question 17). The key's write time is the time of the most recent
    /// search, as for every MRU here.
    WordWheelQuery,
}

impl MruKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RecentDocs => "recent_docs",
            Self::RunMru => "run_mru",
            Self::TypedPaths => "typed_paths",
            Self::OpenSavePidlMru => "open_save_pidl_mru",
            Self::LastVisitedPidlMru => "last_visited_pidl_mru",
            Self::CidSizeMru => "cid_size_mru",
            Self::FirstFolder => "first_folder",
            Self::WordWheelQuery => "word_wheel_query",
        }
    }

    /// Whether this family's bodies carry a shell item — after the display
    /// name, or (`OpenSavePidlMRU`) on their own.
    fn has_shell_item(&self) -> bool {
        matches!(
            self,
            Self::RecentDocs | Self::OpenSavePidlMru | Self::LastVisitedPidlMru
        )
    }
}

/// Recognise an MRU key from its path.
///
/// Matched on **segments**, case-insensitively. `Internet Explorer\TypedURLs`
/// is deliberately **not** matched: it is a different key with a different
/// meaning, already normalised into browser-history records elsewhere, and
/// merging the two would put a filesystem path into a browsing history.
pub fn mru_kind_of(key_path: &str) -> Option<MruKind> {
    let segments: Vec<String> = key_path
        .split('\\')
        .filter(|s| !s.is_empty())
        .skip(1)
        .map(|s| s.to_ascii_lowercase())
        .collect();
    let explorer = segments.iter().position(|s| s == "explorer")?;
    let tail = &segments[explorer + 1..];
    match tail.len() {
        1 => match tail[0].as_str() {
            "recentdocs" => Some(MruKind::RecentDocs),
            "runmru" => Some(MruKind::RunMru),
            "typedpaths" => Some(MruKind::TypedPaths),
            "wordwheelquery" => Some(MruKind::WordWheelQuery),
            _ => None,
        },
        2 => match (tail[0].as_str(), tail[1].as_str()) {
            // A per-extension or `Folder` subkey of RecentDocs.
            ("recentdocs", _) => Some(MruKind::RecentDocs),
            // `OpenSavePidlMRU` is the key Windows writes. The roadmap spelled
            // it `OpenSavePidMRU`; matching that would invent a key, and a
            // matcher built from it finds nothing on any real hive.
            ("comdlg32", "lastvisitedpidlmru" | "lastvisitedmru") => {
                Some(MruKind::LastVisitedPidlMru)
            }
            ("comdlg32", "cidsizemru") => Some(MruKind::CidSizeMru),
            ("comdlg32", "firstfolder") => Some(MruKind::FirstFolder),
            _ => None,
        },
        3 if tail[0] == "comdlg32"
            && matches!(tail[1].as_str(), "opensavepidlmru" | "opensavemru") =>
        {
            Some(MruKind::OpenSavePidlMru)
        }
        _ => None,
    }
}

/// Where an entry's position came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OrderSource {
    /// Named by `MRUListEx`.
    MruListEx,
    /// Named by `MRUList` (RunMRU).
    MruList,
    /// Present on the key and named by neither. A stale entry.
    NotListed,
}

impl OrderSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MruListEx => "MRUListEx",
            Self::MruList => "MRUList",
            Self::NotListed => "not listed in MRUListEx",
        }
    }
}

/// Which ordering convention a key uses.
#[derive(Clone, Debug)]
pub enum OrderKind {
    ListEx,
    List(Vec<String>),
}

/// Decode `MRUListEx`: little-endian `u32` indices, `0xFFFFFFFF`-terminated.
///
/// A trailing partial index is not an index: three spare bytes are dropped
/// rather than padded into a fourth entry.
pub fn parse_mrulistex(bytes: &[u8]) -> Vec<u32> {
    bytes
        .as_chunks::<4>()
        .0
        .iter()
        .map(|c| u32::from_le_bytes(*c))
        .take_while(|&n| n != u32::MAX)
        .collect()
}

/// Decode `MRUList`: UTF-16LE letters in order.
pub fn parse_mrulist(bytes: &[u8]) -> Vec<String> {
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .take_while(|&u| u != 0)
        .map(|u| String::from_utf16_lossy(&[u]))
        .collect()
}

/// Where in the order a value sits, or `None` when the order does not name it.
pub fn position_of(value_name: &str, listex: &[u32], kind: OrderKind) -> Option<usize> {
    match kind {
        OrderKind::ListEx => {
            let n: u32 = value_name.parse().ok()?;
            listex.iter().position(|&i| i == n)
        }
        OrderKind::List(letters) => letters.iter().position(|l| l == value_name),
    }
}

/// One MRU entry.
#[derive(Clone, Debug)]
pub struct ShellMruEntry {
    pub mru_kind: MruKind,
    pub value_name: String,
    pub mru_position: Option<usize>,
    pub order_source: OrderSource,
    pub display_name: Option<String>,
    pub command: Option<String>,
    pub link_name: Option<String>,
    pub extension: Option<String>,
    /// Whether the **deepest** item's own type-specific structure was read
    /// from its documented offsets — `seance_shell_item::ParsedShellItem::parsed`
    /// for that item, and per item rather than a blanket claim (`HUNT-147`).
    pub shell_item_parsed: bool,
    /// The deepest item's MFT file reference, where a version-7+ `BEEF0004`
    /// block carries one. Same fields `seance_plugin_lnk` publishes.
    pub shell_item_mft_entry: Option<u64>,
    pub shell_item_mft_sequence: Option<u16>,
    /// The deepest item's block carries a file-reference field and it is all
    /// zero — what Windows writes when it has none. Stated rather than
    /// published as entry 0 of sequence 0, which would name `$MFT`.
    pub shell_item_mft_reference_zero: bool,
    /// How many items the ID list walk yielded, and how many of those the
    /// decoder could not read past their type byte.
    pub shell_items_total: usize,
    pub shell_items_unread: usize,
    pub shell_item_bytes: Option<Vec<u8>>,
    /// The names the shell item ID list itself encodes, outermost first — a
    /// path, read through `seance_shell_item` and not out of the delimiters
    /// (`HUNT-127`, `ROADMAP` §5.16).
    pub shell_item_path: Vec<String>,
    /// The FAT times on the deepest item, where it carries any. Local
    /// wall-clock with no zone, like every shell-item time.
    pub shell_item_modified: Option<String>,
    pub shell_item_created: Option<String>,
    pub shell_item_accessed: Option<String>,
    /// The bytes after the name in a body that holds a name and no shell item
    /// (`CIDSizeMRU`, `FirstFolder`): kept whole, and not decoded.
    pub value_tail_bytes: Option<Vec<u8>>,
    pub key_path: Option<String>,
    pub key_last_written: Option<String>,
}

impl ShellMruEntry {
    pub fn new(
        mru_kind: MruKind,
        value_name: &str,
        mru_position: Option<usize>,
        order_source: OrderSource,
    ) -> Self {
        Self {
            mru_kind,
            value_name: value_name.to_string(),
            mru_position,
            order_source,
            display_name: None,
            command: None,
            link_name: None,
            extension: None,
            shell_item_parsed: false,
            shell_item_mft_entry: None,
            shell_item_mft_sequence: None,
            shell_item_mft_reference_zero: false,
            shell_items_total: 0,
            shell_items_unread: 0,
            shell_item_bytes: None,
            shell_item_path: Vec::new(),
            shell_item_modified: None,
            shell_item_created: None,
            shell_item_accessed: None,
            value_tail_bytes: None,
            key_path: None,
            key_last_written: None,
        }
    }

    pub fn to_json(&self) -> Value {
        let mut m = serde_json::Map::new();
        let name = self
            .display_name
            .clone()
            .or_else(|| self.command.clone())
            .unwrap_or_else(|| self.value_name.clone());
        m.insert("type".into(), json!("ShellMruEntry"));
        m.insert("name".into(), json!(name));
        m.insert("mru_kind".into(), json!(self.mru_kind.as_str()));
        m.insert("value_name".into(), json!(self.value_name));
        m.insert("mru_position".into(), json!(self.mru_position));
        m.insert("mru_order_source".into(), json!(self.order_source.as_str()));
        if self.order_source == OrderSource::NotListed {
            m.insert(
                "mru_order_note".into(),
                json!(
                    "This value is on the key and the order list does not name it — a stale \
                       entry left after the list shrank. It has no position, because giving it \
                       one would assert an ordering the hive does not record."
                ),
            );
        }
        m.insert("display_name".into(), json!(self.display_name));
        m.insert("command".into(), json!(self.command));
        m.insert("link_name".into(), json!(self.link_name));
        if self.link_name.is_some() {
            m.insert(
                "link_name_basis".into(),
                json!(
                    "the name of the SHORTCUT FILE, read as a NUL-delimited ASCII run in the \
                       shell item's tail — its boundaries come from the delimiters and not \
                       from the format. The item's own names are in `shell_item_path`, which \
                       does come from the format; prefer those."
                ),
            );
        }
        // The names the shell item ID list encodes, read through the format
        // (`HUNT-127`, `ROADMAP` §5.16). One per level, outermost first.
        if !self.shell_item_path.is_empty() {
            m.insert("shell_item_path".into(), json!(self.shell_item_path));
            m.insert("shell_item_name".into(), json!(self.shell_item_path.last()));
            m.insert(
                "shell_item_path_basis".into(),
                json!(
                    "read by walking the shell item ID list and taking each item's own name \
                       out of its structure, through `seance_shell_item`. An item of a type \
                       this build does not know appears as `UnknownType_0x<hex>` rather than \
                       as a guess, so a path may name a level it could not read."
                ),
            );
        }
        for (key, value) in [
            ("shell_item_modified", &self.shell_item_modified),
            ("shell_item_created", &self.shell_item_created),
            ("shell_item_accessed", &self.shell_item_accessed),
        ] {
            if let Some(t) = value {
                m.insert(key.into(), json!(t));
            }
        }
        if self.shell_item_modified.is_some()
            || self.shell_item_created.is_some()
            || self.shell_item_accessed.is_some()
        {
            // These belong to the deepest item, not to the MRU entry — and
            // they are FAT pairs, so local wall-clock with no zone.
            m.insert(
                "shell_item_time_scope".into(),
                json!("the deepest shell item"),
            );
            m.insert("timezone".into(), json!("local"));
            m.insert(
                "shell_item_time_note".into(),
                json!(seance_shell_item::FAT_TIME_NOTE),
            );
        }
        m.insert("extension".into(), json!(self.extension));
        m.insert("key_path".into(), json!(self.key_path));
        m.insert("key_last_written".into(), json!(self.key_last_written));
        m.insert(
            "key_last_written_scope".into(),
            json!("the MRU key, not this entry"),
        );
        // Whose time is whose. Without this, an entry would read as dated.
        m.insert(
            "entry_time_note".into(),
            json!(
                "An MRU entry has no time of its own. Only the key is dated, and its date \
                   belongs to the most recent entry on it."
            ),
        );
        if self.mru_kind.has_shell_item() {
            m.insert("shell_item_parsed".into(), json!(self.shell_item_parsed));
            if let Some(entry) = self.shell_item_mft_entry {
                m.insert("shell_item_mft_entry".into(), json!(entry));
            }
            if let Some(sequence) = self.shell_item_mft_sequence {
                m.insert("shell_item_mft_sequence".into(), json!(sequence));
            }
            if self.shell_item_mft_reference_zero {
                m.insert(
                    "shell_item_mft_reference_note".into(),
                    json!(seance_shell_item::MFT_REFERENCE_ZERO_NOTE),
                );
            }
            if let Some(bytes) = &self.shell_item_bytes {
                m.insert("shell_item_bytes_len".into(), json!(bytes.len()));
                m.insert(
                    "shell_item_bytes_base64".into(),
                    json!(base64::engine::general_purpose::STANDARD.encode(bytes)),
                );
                m.insert("shell_items_total".into(), json!(self.shell_items_total));
                m.insert("shell_items_unread".into(), json!(self.shell_items_unread));
                if let Some(detail) = self.shell_item_incomplete_detail(bytes.len()) {
                    m.insert("content_incomplete".into(), json!(true));
                    m.insert(
                        "content_incomplete_reason".into(),
                        json!(seance_core::io::IncompleteReason::UnresolvedStructure.as_str()),
                    );
                    m.insert("content_incomplete_detail".into(), json!(detail));
                } else {
                    m.insert(
                        "shell_item_decode_scope".into(),
                        json!(SHELL_ITEM_DECODE_SCOPE),
                    );
                }
            }
        }
        if let Some(tail) = &self.value_tail_bytes {
            let all_zero = tail.iter().all(|&b| b == 0);
            m.insert("value_tail_bytes_len".into(), json!(tail.len()));
            m.insert(
                "value_tail_bytes_base64".into(),
                json!(base64::engine::general_purpose::STANDARD.encode(tail)),
            );
            m.insert("value_tail_all_zero".into(), json!(all_zero));
            if !all_zero {
                m.insert("content_incomplete".into(), json!(true));
                m.insert(
                    "content_incomplete_reason".into(),
                    json!(seance_core::io::IncompleteReason::UnresolvedStructure.as_str()),
                );
                m.insert(
                    "content_incomplete_detail".into(),
                    json!(format!(
                        "{} bytes follow the name in this value and were not decoded. They are \
                         not a shell item ID list — this key holds a program's name, which is \
                         what is shown above — and this build does not interpret them. They are \
                         kept above so a later build can.",
                        tail.len()
                    )),
                );
            }
        }
        Value::Object(m)
    }

    /// Why the shell item ID list is short of a full decode, or `None` when
    /// every item it holds was read.
    ///
    /// Two ways to be short, and they are different sentences: the walk
    /// yielded no item at all from a non-empty tail (a list cut short, or
    /// bytes that are not an ID list), or it yielded items and could not
    /// read some of them past their type byte. Both name the number.
    fn shell_item_incomplete_detail(&self, byte_len: usize) -> Option<String> {
        if self.shell_items_total == 0 {
            return Some(format!(
                "{byte_len} bytes of shell-item data could not be walked as a shell item ID \
                 list — no item's declared size fits inside them — so nothing in them was \
                 decoded. Where this family stores an ID list it holds the target's folder \
                 chain and its MFT file reference, so what is shown above is not everything \
                 the hive records about this entry. The bytes are kept above so a later \
                 build can decode them."
            ));
        }
        if self.shell_items_unread > 0 {
            return Some(format!(
                "{} of {} items in the shell item ID list were not decoded past their type \
                 byte: a type this build does not know, a class it names but does not decode \
                 (a root folder, a control panel, a users property view), or an instance too \
                 short for its fields. Each appears in `shell_item_path` as its placeholder \
                 rather than as a guess. The bytes are kept above so a later build can decode \
                 them.",
                self.shell_items_unread, self.shell_items_total
            ));
        }
        None
    }
}

/// Decode a `RunMRU` value: a command, with the `\x01` separator stripped.
pub fn decode_runmru(value_name: &str, stored: &str) -> ShellMruEntry {
    let mut e = ShellMruEntry::new(MruKind::RunMru, value_name, None, OrderSource::NotListed);
    // `RunMRU` appends `\x01` as a separator. Leaving it in would put a control
    // character into a command quoted in a report.
    e.command = Some(stored.trim_end_matches('\u{1}').to_string());
    e
}

/// Decode a body that is a shell item ID list and nothing else — what
/// `OpenSavePidlMRU\<ext>` holds (plaso's `mrulistex_shell_item_list`).
///
/// Reading these through [`decode_shell_body`] took the first UTF-16 NUL
/// pair as the end of a name that is not there: on plaso's `NTUSER-WIN7.DAT`
/// every `OpenSavePidlMRU` entry carried a mojibake `display_name` (the
/// leading GUID item's bytes as text) and a list walked from four bytes into
/// its second item, which is where a `0xBB` byte got read as a file entry
/// named `E`.
pub fn decode_pidl_body(mru_kind: MruKind, value_name: &str, body: &[u8]) -> ShellMruEntry {
    let mut e = ShellMruEntry::new(mru_kind, value_name, None, OrderSource::NotListed);
    if !body.is_empty() {
        e.shell_item_bytes = Some(body.to_vec());
        read_shell_item_fields(&mut e, body);
    }
    e
}

/// Decode a body that is a UTF-16LE name, a NUL, and bytes that are not a
/// shell item — `CIDSizeMRU` and `FirstFolder` (`HUNT-167`).
///
/// Walking these as name-then-ID-list reported every one on plaso's
/// `NTUSER-WIN7.DAT` (nine `CIDSizeMRU`, two `FirstFolder`) as "could not be
/// walked as an ID list": true of the bytes, wrong about what the value is.
/// plaso reads both keys as string MRUs (`mrulistex_string`), the name alone.
/// A `CIDSizeMRU` name sits in a 520-byte NUL-padded field followed by 72
/// bytes this build does not interpret; they are kept and disclosed.
pub fn decode_name_body(mru_kind: MruKind, value_name: &str, body: &[u8]) -> ShellMruEntry {
    let mut e = ShellMruEntry::new(mru_kind, value_name, None, OrderSource::NotListed);
    let units = body.as_chunks::<2>().0;
    let end = units.iter().position(|c| *c == [0, 0]);
    let name_units = &units[..end.unwrap_or(units.len())];
    let name = String::from_utf16_lossy(
        &name_units
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect::<Vec<_>>(),
    );
    if !name.is_empty() {
        e.extension = name
            .rsplit_once('.')
            .map(|(_, ext)| ext.to_ascii_lowercase())
            .filter(|ext| !ext.is_empty() && ext.len() <= 8);
        e.display_name = Some(name);
    }
    // Everything after the name's terminator — or, with no terminator, the
    // odd byte a UTF-16 read could not take.
    let consumed = match end {
        Some(at) => (at + 1) * 2,
        None => name_units.len() * 2,
    };
    let tail = &body[consumed.min(body.len())..];
    if !tail.is_empty() {
        e.value_tail_bytes = Some(tail.to_vec());
    }
    e
}

/// Decode a body of the form: UTF-16LE name, NUL, then a shell item ID list
/// (`RecentDocs`, `LastVisitedPidlMRU`).
pub fn decode_shell_body(mru_kind: MruKind, value_name: &str, body: &[u8]) -> ShellMruEntry {
    let mut e = ShellMruEntry::new(mru_kind, value_name, None, OrderSource::NotListed);

    // Find the UTF-16 NUL that ends the name. Without one, the body is not a
    // name followed by anything — and reading the whole blob as text would
    // render a PIDL as mojibake.
    let units = body.as_chunks::<2>().0;
    let nul_at = units.iter().position(|c| *c == [0, 0]);
    if let Some(at) = nul_at {
        let name: String = String::from_utf16_lossy(
            &units[..at]
                .iter()
                .map(|c| u16::from_le_bytes(*c))
                .collect::<Vec<_>>(),
        );
        if !name.is_empty() {
            e.extension = name
                .rsplit_once('.')
                .map(|(_, ext)| ext.to_ascii_lowercase())
                .filter(|ext| !ext.is_empty() && ext.len() <= 8);
            e.display_name = Some(name);
        }
        let rest = &body[(at + 1) * 2..];
        if !rest.is_empty() {
            e.shell_item_bytes = Some(rest.to_vec());
            // The `.lnk` name Windows writes into the tail, when it is there.
            // Kept because it is a different thing from the item's own name:
            // the shortcut file, not the target.
            e.link_name = ascii_tail_ending_in(rest, ".lnk");
            // And the names the ID list encodes, read through the format.
            read_shell_item_fields(&mut e, rest);
        }
    } else if !body.is_empty() {
        e.shell_item_bytes = Some(body.to_vec());
        read_shell_item_fields(&mut e, body);
    }
    e
}

/// Walk a shell item ID list and take the names and times out of the format.
///
/// This is what `HUNT-127` asked for. The `.lnk` tail above is found by
/// scanning for a NUL-delimited printable run, which is why every name it
/// produced shipped with a note saying its boundaries came from the delimiters
/// rather than the structure. These names come from the items themselves, one
/// per level, and the times from the deepest item that carries any.
fn read_shell_item_fields(e: &mut ShellMruEntry, bytes: &[u8]) {
    let items = seance_shell_item::walk_id_list_detail(bytes);
    e.shell_items_total = items.len();
    e.shell_items_unread = items.iter().filter(|item| !item.parsed).count();
    if items.is_empty() {
        return;
    }
    e.shell_item_path = items.iter().map(|item| item.name.clone()).collect();
    // The deepest item is the thing the entry is about; the ones above it are
    // the folders it sat in.
    if let Some(last) = items.last() {
        let times = seance_shell_item::shell_item_times(&last.raw);
        e.shell_item_modified = times.modified.map(|t| t.to_rfc3339());
        e.shell_item_created = times.created.map(|t| t.to_rfc3339());
        e.shell_item_accessed = times.accessed.map(|t| t.to_rfc3339());
        e.shell_item_parsed = last.parsed;
        if let Some(mft) = &last.mft_reference {
            e.shell_item_mft_entry = Some(mft.entry);
            e.shell_item_mft_sequence = Some(mft.sequence);
        }
        // Every RecentDocs `.lnk` item in NTUSER-WIN7.DAT carries a
        // version-8 block with this field zeroed (38 of 38): Windows writes
        // zero when it has no reference, and `seance_shell_item` reports
        // that as a zero field rather than as entry 0, which would name
        // $MFT.
        e.shell_item_mft_reference_zero = last.mft_reference_zero;
    }
}

/// What a full decode of the ID list did and did not read, stated on the
/// record so "every item parsed" is not read as "every byte interpreted".
const SHELL_ITEM_DECODE_SCOPE: &str = "every item in the shell item ID list was decoded \
    through `seance_shell_item`: each item's own name from its documented field, and on \
    the deepest item its FAT times and, where a version-7 or later BEEF0004 block carries \
    one, its MFT file reference. Other extension blocks, and the fields this reader does \
    not name, were not read; the bytes are kept above in full.";

/// A **NUL-delimited** run of printable ASCII in `bytes` ending in `suffix`.
///
/// # Why the delimiter is required, and what it costs
///
/// A shell item ID list interleaves binary fields with strings, and a PIDL byte
/// that happens to be printable is indistinguishable from the first character
/// of the name that follows it. Scanning for printable runs alone found
/// `OVIBRANIUM.lnk` in this module's own fixture, because `0x4F` is `O`.
///
/// So the run must begin at the start of the slice or immediately after a
/// `0x00`, which is what a stored NUL-terminated string looks like. That errs
/// toward **not extracting** rather than extracting a name with a stray leading
/// character: a report quoting `OVIBRANIUM.lnk` is wrong in a way nobody would
/// catch, and a missing convenience field is not — the shell-item bytes are
/// published in full either way, so nothing is lost that was there.
///
/// Only `0x20..=0x7E`. A name that is not ASCII is left to the bytes.
fn ascii_tail_ending_in(bytes: &[u8], suffix: &str) -> Option<String> {
    let mut best: Option<String> = None;
    let mut run = String::new();
    // A run is only a candidate if it starts where a C string could: at the
    // beginning, or just past a terminator.
    let mut delimited = true;
    for b in bytes {
        if (0x20..=0x7E).contains(b) {
            run.push(*b as char);
        } else {
            if delimited && run.to_ascii_lowercase().ends_with(suffix) {
                best = Some(run.clone());
            }
            run.clear();
            delimited = *b == 0;
        }
    }
    if delimited && run.to_ascii_lowercase().ends_with(suffix) {
        best = Some(run);
    }
    best
}

/// What was found on one MRU key.
#[derive(Clone, Debug)]
pub struct MruCoverage {
    pub mru_kind: MruKind,
    pub key_path: String,
    pub values_total: usize,
    pub entries: usize,
    pub order_indices: usize,
    /// Indices in the order list naming a value the key does not hold.
    pub indices_without_a_value: usize,
    /// Values on the key that the order list does not name.
    pub values_not_in_order: usize,
    pub key_last_written: Option<String>,
}

impl MruCoverage {
    pub fn to_json(&self) -> Value {
        let mut note = format!(
            "{} entr(ies) from {} value(s) on the key.",
            self.entries, self.values_total
        );
        if self.indices_without_a_value > 0 {
            note.push_str(&format!(
                " The order list names {} value(s) this key does not hold, so the list and the \
                 key disagree; both are reported as found.",
                self.indices_without_a_value
            ));
        }
        if self.values_not_in_order > 0 {
            note.push_str(&format!(
                " {} value(s) are on the key and not named by the order list — stale entries \
                 left after it shrank, reported without a position.",
                self.values_not_in_order
            ));
        }
        json!({
            "type": "MruCoverage",
            "name": format!("{} ({})", self.mru_kind.as_str(), self.key_path),
            "mru_kind": self.mru_kind.as_str(),
            "key_path": self.key_path,
            "values_total": self.values_total,
            "entries": self.entries,
            "order_indices": self.order_indices,
            "indices_without_a_value": self.indices_without_a_value,
            "values_not_in_order": self.values_not_in_order,
            "key_last_written": self.key_last_written,
            "coverage_note": note,
        })
    }

    /// The one timeline event this key earns.
    ///
    /// Naming the position-0 entry makes the event useful without attributing
    /// the key's time to every other entry on it.
    pub fn timeline_event(&self, most_recent: Option<&str>) -> Option<Value> {
        let when = self.key_last_written.clone()?;
        Some(json!({
            "type": "TimelineEvent",
            "timestamp": when,
            "timestamp_desc": "MRU key last written",
            "name": format!("{} last written", self.mru_kind.as_str()),
            // The qualification is in BOTH branches. It is the load-bearing
            // half of the sentence -- that this one time does not date the
            // other entries on the key -- and a key whose order list names no
            // most-recent entry needs it just as much as one that does.
            "short_desc": match most_recent {
                Some(entry) => format!(
                    "the most recent entry on this key is {entry}; the key's time is when that \
                     entry was added, and is not the time of any other entry on it"
                ),
                None => "this key's order list names no most-recent entry, so what this write \
                         corresponds to is not recorded; it is not the time of any other entry \
                         on the key"
                    .to_string(),
            },
            "source": "Registry",
            "source_long": format!("Shell MRU ({})", self.key_path),
        }))
    }
}

// --- Outgoing RDP ----------------------------------------------------------

/// Which `Terminal Server Client` key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RdpKeyKind {
    /// `…\Terminal Server Client\Default` — `MRU0..MRUn` destinations.
    Default,
    /// `…\Terminal Server Client\Servers\<host>`.
    Server { host: String },
}

/// Recognise an outgoing-RDP key.
pub fn rdp_key(key_path: &str) -> Option<RdpKeyKind> {
    let segments: Vec<&str> = key_path
        .split('\\')
        .filter(|s| !s.is_empty())
        .skip(1)
        .collect();
    let lower: Vec<String> = segments.iter().map(|s| s.to_ascii_lowercase()).collect();
    let tsc = lower.iter().position(|s| s == "terminal server client")?;
    match lower.len() - tsc {
        2 if lower[tsc + 1] == "default" => Some(RdpKeyKind::Default),
        3 if lower[tsc + 1] == "servers" => Some(RdpKeyKind::Server {
            host: segments[tsc + 2].to_string(),
        }),
        _ => None,
    }
}

/// What `mru_key_last_written_scope` says: the `Default` key's time is the
/// list's, shared by every `MRUn` in it.
const RDP_DEFAULT_SCOPE: &str = "the Terminal Server Client\\Default key, which holds every MRU \
                                 destination; not this destination";
/// What `servers_key_last_written_scope` says: a `Servers\<host>` key belongs
/// to one destination, so its time is that destination's.
const RDP_SERVERS_SCOPE: &str = "this destination's own Servers subkey";

/// One `Terminal Server Client\Servers\<host>` subkey joined into a
/// destination (`HUNT-248`): a destination may have more than one, e.g. `host`
/// and `host:3389`, and each keeps its own path, time and `UsernameHint`.
#[derive(Clone, Debug, Default)]
pub struct RdpServersKey {
    /// The subkey's own name, as stored.
    pub host: String,
    pub path: String,
    pub last_written: Option<String>,
    pub username_hint: Option<String>,
}

impl RdpServersKey {
    fn to_json(&self) -> Value {
        json!({
            "host": self.host,
            "path": self.path,
            "last_written": self.last_written,
            "last_written_scope": RDP_SERVERS_SCOPE,
            "username_hint": self.username_hint,
        })
    }
}

/// One outgoing RDP destination: every `Default\MRUn` naming the host and the
/// host's `Servers\<host>` key, joined by host (`HUNT-243`). A host found in
/// only one of the two keys is still one record, with the other key's fields
/// null. Each key's path and last-written time are carried separately and each
/// time names the key it dates, because the two keys are written at different
/// moments and neither time is "the destination's time" on its own.
#[derive(Clone, Debug, Default)]
pub struct RdpDestinationEntry {
    /// The host as first seen: the MRU value's spelling when it is in the
    /// MRU, else the `Servers` subkey's name.
    pub host: String,
    /// The lowest MRU position naming this host, when it is in the MRU.
    pub mru_position: Option<usize>,
    /// Every MRU position naming this host, ascending.
    pub mru_positions: Vec<usize>,
    /// The first non-null `UsernameHint` among this destination's `Servers`
    /// subkeys; every hint is on its own element of `servers_keys`.
    pub username_hint: Option<String>,
    pub mru_key_path: Option<String>,
    pub mru_key_last_written: Option<String>,
    /// Every spelling of this destination as stored, first-seen first: each
    /// distinct MRU value, then the `Servers` subkey name (`HUNT-245`).
    pub hosts_as_stored: Vec<String>,
    /// The first-seen `Servers` subkey's own name, which may differ in case
    /// or in an explicit `:3389` from `host`. The `servers_key_*` scalars are
    /// that first subkey; `servers_keys` lists every one (`HUNT-248`).
    pub servers_key_host: Option<String>,
    pub servers_key_path: Option<String>,
    pub servers_key_last_written: Option<String>,
    /// Every `Servers` subkey joined into this destination, in key order.
    pub servers_keys: Vec<RdpServersKey>,
}

impl RdpDestinationEntry {
    pub fn to_json(&self) -> Value {
        let in_mru = self.mru_position.is_some();
        let in_servers = self.servers_key_host.is_some();
        // Every distinct hint, first-seen first, so a second subkey's hint is
        // visible rather than silently lost behind `username_hint`.
        let mut username_hints: Vec<String> = Vec::new();
        for h in self
            .servers_keys
            .iter()
            .filter_map(|k| k.username_hint.as_deref())
        {
            note_spelling(&mut username_hints, h);
        }
        json!({
            "type": "RdpDestinationEntry",
            "name": self.host,
            "host": self.host,
            "mru_position": self.mru_position,
            "mru_positions": self.mru_positions,
            "username_hint": self.username_hint,
            "in_mru_list": in_mru,
            "in_servers_key": in_servers,
            "mru_key_path": self.mru_key_path,
            "mru_key_last_written": self.mru_key_last_written,
            "mru_key_last_written_scope": in_mru.then_some(RDP_DEFAULT_SCOPE),
            "destination": rdp_destination_key(&self.host),
            "hosts_as_stored": self.hosts_as_stored,
            "servers_key_host": self.servers_key_host,
            "servers_key_path": self.servers_key_path,
            "servers_key_last_written": self.servers_key_last_written,
            "servers_key_last_written_scope": in_servers.then_some(RDP_SERVERS_SCOPE),
            "servers_key_count": self.servers_keys.len(),
            "servers_keys": self.servers_keys.iter().map(RdpServersKey::to_json).collect::<Vec<_>>(),
            "username_hints": username_hints,
            "join_basis": RDP_JOIN_BASIS,
            // Stated as a field, not only in prose, so a reader filtering on
            // it sees that an IP and a name for one machine stay two records.
            "ip_to_name_join_attempted": false,
            // The direction people most often get backwards with this key.
            "direction_note": "an outgoing connection attempted from this machine: the \
                               destination was entered in the Remote Desktop client here. It \
                               is not a record of anything connecting TO this machine.",
            // And what it does not establish.
            "connection_succeeded": false,
            "basis": "the client stored this destination because it was entered; the key does \
                      not record whether a connection was established, or by whom",
        })
    }
}

/// What `join_basis` says on every destination record.
const RDP_JOIN_BASIS: &str = "one record per destination: every Default\\MRUn value naming it \
     and its Servers\\<host> subkey, matched on the host compared case-insensitively as \
     Windows compares host names, with an explicit :3389 — the Remote Desktop client's \
     default port — treated as no port, so 'host' and 'host:3389' are one destination and \
     'host:3390' is another. The name as typed is otherwise matched; an IP address and a \
     host name for the same machine are not resolved to each other (the hive holds no \
     evidence that they are one machine) and stay two records. A destination with more than one Servers \
     subkey (e.g. 'host' and 'host:3389') is still one record: servers_keys lists every \
     subkey with its own path, time and UsernameHint, username_hints every distinct hint, \
     and the servers_key_* fields are the first subkey seen. username_hint is the first non-null hint \
     in that order and may come from a later subkey than servers_key_path and \
     servers_key_last_written; servers_keys pairs each hint with its own key.";

/// The Remote Desktop client's default port.
const RDP_DEFAULT_PORT: u16 = 3389;

/// The key a destination is joined on (`HUNT-245`): the host lower-cased, with
/// an explicit default port removed. `host:port` splits on the only colon;
/// `[v6]:port` on the colon after the bracket; an unbracketed IPv6 address
/// (more than one colon) carries no port and is taken whole. A port that is
/// not the default, or not a number, stays part of the key.
pub fn rdp_destination_key(host: &str) -> String {
    let h = host.trim().to_ascii_lowercase();
    let split = if h.starts_with('[') {
        h.rfind("]:").map(|i| (&h[..=i], &h[i + 2..]))
    } else if h.matches(':').count() == 1 {
        h.split_once(':')
    } else {
        None
    };
    match split {
        Some((name, port)) if port.parse::<u16>().ok() == Some(RDP_DEFAULT_PORT) => {
            name.to_string()
        }
        _ => h,
    }
}

fn note_spelling(spellings: &mut Vec<String>, s: &str) {
    if !spellings.iter().any(|x| x == s) {
        spellings.push(s.to_string());
    }
}

/// Join the `Default` MRU destinations and the `Servers\<host>` keys into one
/// record per destination ([`rdp_destination_key`]: case-insensitive, default
/// port normalised). MRU hosts come first, in MRU order; hosts only in
/// `Servers` follow, in key order.
pub fn join_rdp_destinations(
    mru: Vec<RdpDestinationEntry>,
    servers: Vec<RdpDestinationEntry>,
) -> Vec<RdpDestinationEntry> {
    let mut out: Vec<RdpDestinationEntry> = Vec::new();
    for mut e in mru {
        let key = rdp_destination_key(&e.host);
        match out.iter_mut().find(|o| rdp_destination_key(&o.host) == key) {
            Some(o) => {
                o.mru_positions.extend(e.mru_positions);
                o.mru_positions.sort_unstable();
                o.mru_positions.dedup();
                o.mru_position = o.mru_positions.first().copied();
                note_spelling(&mut o.hosts_as_stored, &e.host);
            }
            None => {
                let host = e.host.clone();
                note_spelling(&mut e.hosts_as_stored, &host);
                out.push(e);
            }
        }
    }
    for mut s in servers {
        let key = rdp_destination_key(&s.host);
        match out.iter_mut().find(|o| rdp_destination_key(&o.host) == key) {
            Some(o) => {
                note_spelling(&mut o.hosts_as_stored, &s.host);
                // The scalars stay the first subkey seen; every subkey goes
                // on the list (`HUNT-248`).
                if o.servers_key_host.is_none() {
                    o.servers_key_host = s.servers_key_host;
                    o.servers_key_path = s.servers_key_path;
                    o.servers_key_last_written = s.servers_key_last_written;
                }
                // The first non-null hint, which may be a later subkey's
                // than the `servers_key_*` scalars; `join_basis` says so.
                if o.username_hint.is_none() {
                    o.username_hint = s.username_hint;
                }
                o.servers_keys.extend(s.servers_keys);
            }
            None => {
                let host = s.host.clone();
                note_spelling(&mut s.hosts_as_stored, &host);
                out.push(s);
            }
        }
    }
    out
}

/// Decode a `Default` key's `MRU0..MRUn` destinations, in order.
pub fn decode_rdp_default(values: &[(String, String)]) -> Vec<RdpDestinationEntry> {
    let mut out: Vec<(usize, RdpDestinationEntry)> = values
        .iter()
        .filter_map(|(name, data)| {
            let n: usize = name
                .to_ascii_uppercase()
                .strip_prefix("MRU")?
                .parse()
                .ok()?;
            Some((
                n,
                RdpDestinationEntry {
                    host: data.clone(),
                    mru_position: Some(n),
                    mru_positions: vec![n],
                    ..Default::default()
                },
            ))
        })
        .collect();
    out.sort_by_key(|(n, _)| *n);
    out.into_iter().map(|(_, e)| e).collect()
}

/// Turn the walk's capture into records.
///
/// One coverage record per MRU key, one entry per value, and exactly **one**
/// timeline event per key naming its position-0 entry — the only date the hive
/// gives for these.
pub fn emit(capture: &crate::resident::ResidentCapture) -> Vec<Value> {
    use crate::resident::Anchor;

    let mut out = Vec::new();
    for key in capture.keys_matching(|a| matches!(a, Anchor::Mru { .. })) {
        let Anchor::Mru { kind } = &key.anchor else {
            continue;
        };
        let kind = *kind;
        let key_last_written = seance_core::time::filetime_to_rfc3339(key.last_written_filetime);

        // The order list, whichever convention this key uses.
        let listex: Vec<u32> = key
            .values
            .iter()
            .find(|v| v.name.eq_ignore_ascii_case("MRUListEx"))
            .map(|v| parse_mrulistex(&v.data))
            .unwrap_or_default();
        let list: Vec<String> = key
            .values
            .iter()
            .find(|v| v.name.eq_ignore_ascii_case("MRUList"))
            .map(|v| parse_mrulist(&v.data))
            .unwrap_or_default();
        let order_kind = || {
            if list.is_empty() {
                OrderKind::ListEx
            } else {
                OrderKind::List(list.clone())
            }
        };
        let order_indices = if list.is_empty() {
            listex.len()
        } else {
            list.len()
        };

        let mut entries: Vec<ShellMruEntry> = Vec::new();
        let mut values_not_in_order = 0usize;
        for value in &key.values {
            // The order lists are the key's own bookkeeping, not entries.
            if value.name.eq_ignore_ascii_case("MRUListEx")
                || value.name.eq_ignore_ascii_case("MRUList")
            {
                continue;
            }
            let position = position_of(&value.name, &listex, order_kind());
            let source = match (position, list.is_empty()) {
                (Some(_), true) => OrderSource::MruListEx,
                (Some(_), false) => OrderSource::MruList,
                (None, _) => {
                    values_not_in_order += 1;
                    OrderSource::NotListed
                }
            };
            let mut entry = match kind {
                // `RunMRU` and `TypedPaths` store a string, not a shell item.
                MruKind::RunMru => {
                    let stored = utf16le(&value.data);
                    let mut e = decode_runmru(&value.name, &stored);
                    e.mru_position = position;
                    e.order_source = source;
                    e
                }
                MruKind::TypedPaths => {
                    let mut e = ShellMruEntry::new(kind, &value.name, position, source);
                    e.display_name = Some(utf16le(&value.data));
                    e
                }
                // Vista+ `OpenSavePidlMRU` holds a bare ID list; XP's
                // `OpenSaveMRU` (the same anchor) holds a `REG_SZ` path. The
                // value's own type says which, and neither is a name followed
                // by a list.
                MruKind::OpenSavePidlMru => {
                    let mut e = if matches!(
                        value.data_type,
                        Some(KeyValueDataType::RegSZ | KeyValueDataType::RegExpandSZ)
                    ) {
                        let mut e = ShellMruEntry::new(kind, &value.name, None, source.clone());
                        e.display_name = Some(utf16le(&value.data));
                        e
                    } else {
                        decode_pidl_body(kind, &value.name, &value.data)
                    };
                    e.mru_position = position;
                    e.order_source = source;
                    e
                }
                MruKind::CidSizeMru | MruKind::FirstFolder | MruKind::WordWheelQuery => {
                    let mut e = decode_name_body(kind, &value.name, &value.data);
                    e.mru_position = position;
                    e.order_source = source;
                    e
                }
                _ => {
                    let mut e = decode_shell_body(kind, &value.name, &value.data);
                    e.mru_position = position;
                    e.order_source = source;
                    e
                }
            };
            entry.key_path = Some(key.key_path.clone());
            entry.key_last_written = key_last_written.clone();
            entries.push(entry);
        }

        // Indices the list names for which no value exists. The list and the
        // key disagreeing is a fact about the hive, not a rounding error.
        let present: std::collections::BTreeSet<String> =
            entries.iter().map(|e| e.value_name.clone()).collect();
        let indices_without_a_value = if list.is_empty() {
            listex
                .iter()
                .filter(|i| !present.contains(&i.to_string()))
                .count()
        } else {
            list.iter().filter(|l| !present.contains(*l)).count()
        };

        let coverage = MruCoverage {
            mru_kind: kind,
            key_path: key.key_path.clone(),
            values_total: key.values.len(),
            entries: entries.len(),
            order_indices,
            indices_without_a_value,
            values_not_in_order,
            key_last_written: key_last_written.clone(),
        };
        let most_recent = entries.iter().find(|e| e.mru_position == Some(0)).map(|e| {
            e.display_name
                .clone()
                .or_else(|| e.command.clone())
                .unwrap_or_else(|| e.value_name.clone())
        });
        if let Some(event) = coverage.timeline_event(most_recent.as_deref()) {
            out.push(event);
        }
        out.push(coverage.to_json());
        out.extend(entries.iter().map(ShellMruEntry::to_json));
    }

    // Outgoing RDP: collected from both keys, then joined by host so a
    // destination in `Default` and `Servers` is one record (`HUNT-243`).
    let mut rdp_mru = Vec::new();
    let mut rdp_servers = Vec::new();
    for key in capture.keys_matching(|a| matches!(a, Anchor::Rdp { .. })) {
        let Anchor::Rdp { kind } = &key.anchor else {
            continue;
        };
        let key_last_written = seance_core::time::filetime_to_rfc3339(key.last_written_filetime);
        match kind {
            RdpKeyKind::Default => {
                let values: Vec<(String, String)> = key
                    .values
                    .iter()
                    .map(|v| (v.name.clone(), utf16le(&v.data)))
                    .collect();
                for mut e in decode_rdp_default(&values) {
                    e.mru_key_path = Some(key.key_path.clone());
                    e.mru_key_last_written = key_last_written.clone();
                    rdp_mru.push(e);
                }
            }
            RdpKeyKind::Server { host } => {
                let username_hint = key
                    .values
                    .iter()
                    .find(|v| v.name.eq_ignore_ascii_case("UsernameHint"))
                    .map(|v| utf16le(&v.data));
                rdp_servers.push(RdpDestinationEntry {
                    host: host.clone(),
                    servers_keys: vec![RdpServersKey {
                        host: host.clone(),
                        path: key.key_path.clone(),
                        last_written: key_last_written.clone(),
                        username_hint: username_hint.clone(),
                    }],
                    username_hint,
                    servers_key_host: Some(host.clone()),
                    servers_key_path: Some(key.key_path.clone()),
                    servers_key_last_written: key_last_written.clone(),
                    ..Default::default()
                });
            }
        }
    }
    out.extend(
        join_rdp_destinations(rdp_mru, rdp_servers)
            .iter()
            .map(RdpDestinationEntry::to_json),
    );
    out
}

/// Decode a `REG_SZ` body: UTF-16LE, NUL-terminated.
fn utf16le(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .take_while(|&u| u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}
