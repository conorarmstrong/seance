//! Stored archive entry names, resolved into the flat-model path contract.
//!
//! TAR headers and 7z name blocks both carry a path chosen by whoever built the
//! archive, and a hostile one is an ordinary thing to meet in evidence. One
//! resolver serves every extractor in this crate so the rule cannot drift
//! between the formats it protects.

/// The flat-model path fields for one archive entry, derived from its stored
/// name.
pub(crate) struct EntryPath {
    /// `/`-prefixed path, resolved within the archive root.
    pub(crate) full_path: String,
    /// Containing directory (`/` at the archive root).
    pub(crate) parent_path: String,
    /// Basename.
    pub(crate) name: String,
    /// The stored name, verbatim, when resolution changed it. The traversal
    /// attempt is evidence in its own right, so it is kept rather than dropped
    /// — and it is the name that still addresses the entry in the archive.
    pub(crate) original: Option<String>,
    /// The stored name reaches outside the archive root: it is absolute, or a
    /// `..` walks past the root.
    pub(crate) escapes_root: bool,
}

/// Resolve a stored archive entry name into the flat-model `name` / `path` /
/// `parent_path` trio.
///
/// Entry names come from the archive, not from us: `..`, absolute names and
/// doubled separators all occur in hostile archives, and a stored path that
/// keeps them states a location the entry does not occupy — the file tree, the
/// `/files` API and the export manifest all render that path as fact (BUG-036).
/// Empty and `.` segments are dropped, `..` is applied within the archive and
/// clamped at its root. Nothing is destroyed: a name that changed is kept in
/// `original`, and a name that reached outside the root is flagged.
///
/// The same rule is applied to zip entries by `seance_container_zip`, which
/// carries its own copy; every archive format feeds one flat-model path
/// contract, so they must agree.
pub(crate) fn resolve_entry_path(raw: &str) -> EntryPath {
    let trimmed = raw.trim_end_matches('/');
    // An absolute name escapes an extraction root exactly as `..` does.
    let mut escapes_root = trimmed.starts_with('/');
    let mut segments: Vec<&str> = Vec::new();
    for segment in trimmed.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                if segments.pop().is_none() {
                    escapes_root = true;
                }
            }
            other => segments.push(other),
        }
    }
    let resolved = segments.join("/");
    let (parent_path, name) = match resolved.rfind('/') {
        Some(i) => (
            format!("/{}", &resolved[..i]),
            resolved[i + 1..].to_string(),
        ),
        None if !resolved.is_empty() => ("/".to_string(), resolved.clone()),
        // Nothing survived resolution (a name that is only `.` or `..`): the
        // entry sits at the root, but its stored basename stays visible — a
        // nameless row reads as a file that was not there.
        None => (
            "/".to_string(),
            trimmed.rsplit('/').next().unwrap_or_default().to_string(),
        ),
    };
    EntryPath {
        full_path: format!("/{resolved}"),
        parent_path,
        name,
        original: (resolved != trimmed).then(|| raw.to_string()),
        escapes_root,
    }
}

/// Resolve a stored 7z entry name, treating `\` as a separator as well as `/`.
///
/// This is the defence RUSTSEC-2026-0245 was filed for. 7z carries
/// Windows-authored names, so `..\..\payload` is a real escape vector on every
/// platform — `sevenz-rust2`'s own extractor normalises backslashes before its
/// traversal check for exactly that reason, and the version this crate used to
/// depend on did not. Refusing `../x` while honouring `..\x` would leave the
/// advisory's own test case unanswered.
///
/// The TAR resolver deliberately does not do this: a backslash is an ordinary
/// character in a POSIX file name, so splitting on it there would invent
/// directories that the archive never contained.
///
/// The stored name survives verbatim in `original` even when only the separator
/// changed — the exact bytes the archive carried are what a report has to quote,
/// and they are what still addresses the entry inside the archive.
pub(crate) fn resolve_sevenz_entry_path(raw: &str) -> EntryPath {
    let normalized = raw.replace('\\', "/");
    let mut resolved = resolve_entry_path(&normalized);
    if normalized != raw {
        resolved.original = Some(raw.to_string());
    }
    resolved
}
