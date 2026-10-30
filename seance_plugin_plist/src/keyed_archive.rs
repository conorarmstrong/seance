//! Resolving `NSKeyedArchiver` plists into the object graph they encode.
//!
//! # Why the raw form is not enough
//!
//! Most property lists on a modern macOS or iOS device are not
//! key-value dictionaries. They are `NSKeyedArchiver` archives: a flat
//! `$objects` array, a `$top` naming the roots, and a graph of **UID
//! references** knitting them together. macOS stores recent items, login
//! items, shared file lists, Dock configuration and a great deal of application
//! state this way.
//!
//! Rendered literally, such a file is a numbered list of fragments and a set of
//! `UID(n)` strings. Every value is technically present — a keyword search will
//! still hit a URL in `$objects` — but the *structure* is gone, and structure is
//! what says which account a token belonged to, or which file a recent-items
//! entry named. An examiner given the flat form has to dereference it by hand.
//!
//! # What resolution does and does not change
//!
//! It rebuilds the graph. It does not alter, drop or reinterpret any value: a
//! string in `$objects` is the same string once resolved, and this module adds
//! no field that was not in the archive.
//!
//! The raw form is **kept alongside** the resolved one. Resolution follows
//! references and makes decisions about cycles, and an examiner must be able to
//! see what was actually on disk rather than only this module's reading of it.
//!
//! # Cycles
//!
//! Object graphs are graphs, not trees: a parent may reference a child that
//! references the parent. Following one naively does not terminate. A reference
//! already open on the current path is emitted as a marker naming the index it
//! points at, so the shape is preserved, the reader can see where the loop
//! closed, and the walk finishes.

use plist::{Dictionary, Value};
use serde_json::json;

/// How deep the walk may go before it stops descending.
///
/// A bound on a structure taken from evidence, not an estimate of what is
/// reasonable. Real archives nest a few levels; a crafted one can nest until
/// the stack gives out.
const MAX_DEPTH: usize = 64;

/// How many objects may be resolved in one archive.
///
/// The graph can revisit an object many times legitimately — that is what makes
/// it a graph — so a bound on total work is needed as well as on depth.
const MAX_RESOLUTIONS: usize = 100_000;

/// How many JSON values the resolved form may hold.
///
/// Depth and resolution count bound the *walk*; neither bounds the **output**.
/// A graph where many parents share the same children is shallow, acyclic, and
/// well inside the resolution count, and inlining it produces a tree
/// exponentially larger than the file — which is the shape of a compiled `.nib`,
/// and what took the server to 28 GB resident on a folder of them (`HUNT-112`).
const MAX_NODES: usize = 200_000;

/// How many bytes of leaf content (string values, and the bytes of every nested
/// plist a walker opens) the transient tree may accumulate across every
/// resolution of one file — the top-level archive and every archive nested
/// inside an `NSData` member share it through one [`Budget`] (`HUNT-146`).
///
/// `MAX_DEPTH`, `MAX_RESOLUTIONS` and `MAX_NODES` bound the *shape* of the
/// walk — how deep, how tangled, how many values — but none of them bound how
/// large any single value is. A `.nib`-shaped graph reuses a handful of large
/// strings (class names, keys, resource text) from many different objects;
/// each reference is a distinct resolution on a distinct path, so it is not a
/// cycle and is not caught by the node count either, since the node count
/// stays in the thousands while each visit clones the full string. Five
/// thousand references to one 2 MiB string is ~10 GB inlined and nowhere near
/// `MAX_NODES` or `MAX_RESOLUTIONS` — the transient tree a directory walk's
/// resident set traced to, after the output itself was already capped
/// (`HUNT-114` residual).
const MAX_TRANSIENT_BYTES: usize = 4 * 1024 * 1024;

/// Whether a dictionary is an `NSKeyedArchiver` archive.
///
/// All three parts are required. A plist that merely has a `$objects` key is
/// not an archive, and treating it as one would rearrange a file that was
/// already in the form its author intended.
pub fn is_keyed_archive(dict: &Dictionary) -> bool {
    matches!(dict.get("$archiver"), Some(Value::String(a)) if a == "NSKeyedArchiver")
        && matches!(dict.get("$objects"), Some(Value::Array(_)))
        && dict.contains_key("$top")
}

/// Resolve an archive into the graph it encodes.
///
/// `None` when the plist is not an archive, so a caller can fall back to the
/// literal rendering without having to decide.
pub fn resolve(dict: &Dictionary) -> Option<serde_json::Value> {
    resolve_with_budget(dict, MAX_NODES)
}

/// The allowance every resolution of one file shares.
///
/// An archive can hold another archive inside an `NSData` member, and the outer
/// graph can refer to that member from as many places as it likes. Each
/// reference used to open the nested archive with a fresh walker and a fresh
/// allowance, so the bounds held per archive and the file as a whole was
/// bounded by nothing: one nested archive referred to sixty-four times cost
/// sixty-four allowances (`HUNT-146`). One `Budget` is made per file and
/// threaded through every walker and every nested plist opened under it.
pub struct Budget {
    /// JSON values emitted so far, across every walker.
    nodes: usize,
    /// How many the caller can carry.
    max_nodes: usize,
    /// Bytes of leaf content — strings, and the bytes of every nested plist a
    /// walker opened — charged so far. See `MAX_TRANSIENT_BYTES`.
    bytes: usize,
    /// References followed so far, across every walker.
    resolutions: usize,
    /// The bound that first stopped any walker on this budget — the top-level
    /// resolution or an archive nested inside a `Data` value. The record reads
    /// it to stamp `content_incomplete` whatever the rendered size (HUNT-223).
    first_stop: Option<&'static str>,
}

impl Budget {
    /// A budget of `max_nodes` output values, `MAX_RESOLUTIONS` references and
    /// `MAX_TRANSIENT_BYTES` of leaf content.
    pub fn new(max_nodes: usize) -> Self {
        Self {
            nodes: 0,
            max_nodes,
            bytes: 0,
            resolutions: 0,
            first_stop: None,
        }
    }

    /// The bound that first stopped a resolution drawing on this budget, if
    /// any did.
    pub fn first_stop(&self) -> Option<&'static str> {
        self.first_stop
    }

    /// Record that a bound outside any walker stopped part of the file from
    /// being read — a nested plist left unopened at the plist nesting bound
    /// (HUNT-231) — so the record stamps it as a stopped resolution is.
    pub(crate) fn note_stop(&mut self, reason: &'static str) {
        if self.first_stop.is_none() {
            self.first_stop = Some(reason);
        }
    }
}

/// Resolve an archive, stopping once `max_nodes` values have been emitted.
///
/// The caller knows what it can carry. A record holds at most
/// `CONTENT_CAP_BYTES` of JSON, so resolving 200,000 nodes and then discarding
/// the result — which is what a folder of compiled `.nib` files made the parser
/// do, at about 45 MB of transient allocation per file — is work spent on
/// something nothing will read (`HUNT-112`).
pub fn resolve_with_budget(dict: &Dictionary, max_nodes: usize) -> Option<serde_json::Value> {
    resolve_in(dict, &mut Budget::new(max_nodes), 0)
}

/// Resolve an archive against a budget shared with every other resolution of
/// the same file, at plist nesting depth `plist_depth` — the number of `Data`
/// members already opened to reach this archive.
///
/// Both are threaded into the walk, so an `NSData` member holding a further
/// plist is opened one level deeper and charged to the same allowance, rather
/// than restarting at depth 0 with an allowance of its own (`HUNT-177`,
/// `HUNT-146`).
pub fn resolve_in(
    dict: &Dictionary,
    budget: &mut Budget,
    plist_depth: usize,
) -> Option<serde_json::Value> {
    if !is_keyed_archive(dict) {
        return None;
    }
    let Some(Value::Array(objects)) = dict.get("$objects") else {
        return None;
    };
    let top = dict.get("$top")?;

    let mut walker = Walker {
        objects,
        open: Vec::new(),
        budget,
        plist_depth,
        truncated: false,
        truncation_reason: None,
    };
    let resolved = walker.value(top, 0);

    Some(json!({
        "root": resolved,
        // Said plainly rather than left for a reader to infer from the shape.
        "resolved_from": "NSKeyedArchiver",
        "object_count": objects.len(),
        "truncated": walker.truncated,
        // Which bound stopped it, because they mean different things: an
        // archive too deep to follow, one too tangled to walk, and one whose
        // resolved form would not fit are three different findings.
        "truncation_reason": walker.truncation_reason,
    }))
}

struct Walker<'a, 'b> {
    objects: &'a [Value],
    /// UID indices open on the current path — the cycle check.
    open: Vec<u64>,
    /// The file's shared allowance: output values (the bound on the *output*,
    /// as distinct from the bound on the walk), references followed, and bytes
    /// of leaf content (the bound on the *size* of the transient tree, as
    /// distinct from how many values it holds).
    budget: &'b mut Budget,
    /// How many `Data` members were opened to reach this archive; a nested
    /// plist met in this walk is opened at this depth, not at 0.
    plist_depth: usize,
    truncated: bool,
    truncation_reason: Option<&'static str>,
}

impl Walker<'_, '_> {
    fn value(&mut self, value: &Value, depth: usize) -> serde_json::Value {
        self.budget.nodes += 1;
        if depth > MAX_DEPTH {
            return self.stop("nesting depth");
        }
        if self.budget.resolutions > MAX_RESOLUTIONS {
            return self.stop("resolution count");
        }
        if self.budget.nodes > self.budget.max_nodes {
            return self.stop("output size");
        }
        match value {
            Value::Uid(uid) => self.follow(uid.get(), depth),
            // A container stops at the first child that hit a bound: the
            // bound is on the output, and an array of a million elements
            // walked to its end past the budget yields a million truncation
            // markers — which is the output the budget exists to refuse. On a
            // folder of 34,000 property lists those markers were most of a
            // ten-gigabyte resident set (HUNT-114).
            Value::Array(items) => {
                let mut out = Vec::new();
                for v in items {
                    if self.truncated {
                        break;
                    }
                    out.push(self.value(v, depth + 1));
                }
                json!(out)
            }
            Value::Dictionary(map) => {
                // `$class` names the archived type. It is kept, because knowing
                // a dictionary was an NSURL rather than an NSString is often
                // the point.
                let mut converted = serde_json::Map::new();
                for (k, v) in map {
                    if self.truncated {
                        break;
                    }
                    converted.insert(k.clone(), self.value(v, depth + 1));
                }
                json!(converted)
            }
            // A string is the one scalar whose size is not bounded elsewhere
            // in this walk: depth, resolution count and node count all bound
            // how the graph is shaped, not how large one leaf is. Checked
            // before cloning it, not after, so the byte this would have cost
            // is never paid — a value that alone would blow the budget is
            // replaced by a marker, not built and then discarded.
            Value::String(s) => {
                if self.budget.bytes.saturating_add(s.len()) > MAX_TRANSIENT_BYTES {
                    return self.stop("transient bytes");
                }
                self.budget.bytes += s.len();
                json!(s)
            }
            // An `NSData` member holding a plist of its own is opened, and the
            // opening is the one other leaf whose size nothing above bounds: a
            // graph may refer to the same member from every object it holds,
            // and each reference renders the nested plist again. Its bytes are
            // charged before it is opened, to the same allowance as the
            // strings (`HUNT-146`).
            Value::Data(bytes) if crate::opens_as_nested_plist(bytes, self.plist_depth) => {
                if self.budget.bytes.saturating_add(bytes.len()) > MAX_TRANSIENT_BYTES {
                    return self.stop("transient bytes");
                }
                self.budget.bytes += bytes.len();
                crate::nested_or_opaque(bytes, self.plist_depth, self.budget)
            }
            // Rendered at this walk's plist depth with this file's budget —
            // never a fresh start at depth 0 (`HUNT-177`).
            other => crate::plist_value_to_json_in(other, self.plist_depth, self.budget),
        }
    }

    /// Stop here, and record which bound stopped it. The first bound reached is
    /// the one reported: a walk that runs out of room for its output has not
    /// also run out of depth.
    fn stop(&mut self, reason: &'static str) -> serde_json::Value {
        self.truncated = true;
        if self.truncation_reason.is_none() {
            self.truncation_reason = Some(reason);
        }
        if self.budget.first_stop.is_none() {
            self.budget.first_stop = Some(reason);
        }
        json!({ "$truncated": reason })
    }

    fn follow(&mut self, index: u64, depth: usize) -> serde_json::Value {
        self.budget.resolutions += 1;

        // A reference already open on this path closes a cycle. Naming the
        // index preserves the shape and shows the reader where it closed.
        if self.open.contains(&index) {
            return json!({ "$cycle_to_object": index });
        }
        let Some(target) = self.objects.get(index as usize) else {
            // A reference outside the array is a fact about the file, not
            // something to pass off as an absent value.
            return json!({ "$dangling_reference": index });
        };

        // Index 0 is conventionally the string "$null", which is how the format
        // spells an absent object.
        if let Value::String(s) = target {
            if s == "$null" {
                return serde_json::Value::Null;
            }
        }

        self.open.push(index);
        let resolved = self.value(target, depth + 1);
        self.open.pop();
        resolved
    }
}

#[cfg(test)]
mod tests;
