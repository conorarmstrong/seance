//! Layered keys: the differencing hives (minor version 6) a Windows container
//! stacks over a base hive, and the merged view Windows builds from them.
//!
//! # What a layer chain is
//!
//! A Windows container image is a base layer holding full hives
//! (`Files/Windows/System32/config/SYSTEM`, ...) and upper layers each holding
//! a *differencing* hive per base hive (`Hives/System_Delta`, ...): regf minor
//! version 6, base-block flag `0x2`. A differencing hive holds only what that
//! layer changed, plus the ancestor keys needed to reach it. What the running
//! container saw is the **merge** of the whole chain, not any one file; a
//! differencing hive read on its own is a list of changes, not a registry.
//!
//! # The rules, from the specification
//!
//! Maxim Suhanov's *Windows registry file format specification* (CC BY 4.0),
//! "Layered keys". Each key node in a differencing hive carries a byte at
//! `nk+0x0D`: bits 0-1 *Layer semantics*, bit 7 *Inherit class*. To present a
//! key, Windows builds a stack of the key's nodes from the most derived layer
//! towards the base, and:
//!
//! * **0** — the node joins the stack and the walk goes on to the layer below;
//! * **1 `IsTombstone`** — the key is deleted here: neither this node nor any
//!   below it joins. A tombstone that is the most derived node hides the key;
//! * **2 `IsSupersedeLocal`** — the node joins and the walk stops;
//! * **3 `IsSupersedeTree`** — the node joins and the walk stops, and its
//!   subkeys are required to carry the same value.
//!
//! Values are the union over the stack, the most derived node winning a
//! name, and a tombstoned value (`vk` flag `0x2`) hiding the name. The
//! last-written time is the newest in the stack. The class name is that of
//! the most derived node whose *Inherit class* bit is clear.
//!
//! # What this reader decides that the specification does not state
//!
//! Stated so an examiner can read the paragraph aloud, not discover it.
//!
//! * **Subkeys below a supersede.** The specification says a superseding
//!   node's "parent" nodes cannot join *that key's* stack; it does not spell
//!   out the children. This reader takes the names at their word: under
//!   `SupersedeTree` (and below a tombstone) the lower layers' subkeys are
//!   hidden; under `SupersedeLocal` only the key's own stack is cut, and the
//!   lower layers' subkeys still merge. The real chains graded in
//!   `docs/SPEC_CROSSCHECK.md` do not contain a case that distinguishes the
//!   two, so this is interpretation, labelled as such.
//! * **Name matching.** Layers are matched by name, case-insensitively, as
//!   Windows matches them. This reader folds with Unicode simple uppercase,
//!   one character to one; Windows uses its own upcase table, and the two can
//!   differ on a handful of non-ASCII characters. Every name in the real
//!   chains is ASCII.
//! * **Nothing is dropped.** A value a more derived layer hides is returned as
//!   `shadowed`, a tombstone as `tombstoned`, and a layer whose part would not
//!   read as a `LayerFault`: the merged view is the answer to "what did the
//!   container see", and the hidden parts are the evidence of how it got
//!   there.

/// The two-bit *Layer semantics* field of a key node in a differencing hive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LayerSemantics {
    /// 0: this node and the nodes below it in the stack are merged.
    None = 0,
    /// 1 (`IsTombstone`): the key is deleted at this layer.
    Tombstone = 1,
    /// 2 (`IsSupersedeLocal`): this node hides the key's nodes below it.
    SupersedeLocal = 2,
    /// 3 (`IsSupersedeTree`): as `SupersedeLocal`, for the whole subtree.
    SupersedeTree = 3,
}

/// The layered-key bit fields at `nk+0x0D`, as read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LayeredKeyBits {
    pub semantics: LayerSemantics,
    pub inherit_class: bool,
    pub raw: u8,
}

/// The base-block minor version of a differencing hive: the first whose key
/// nodes carry layered-key bit fields.
pub const LAYERED_MINOR_VERSION: u32 = 6;

/// `nk+0x0D` bits 0-1.
const LAYER_SEMANTICS_MASK: u8 = 0x03;
/// `nk+0x0D` bit 7.
const INHERIT_CLASS: u8 = 0x80;

impl LayeredKeyBits {
    /// Decode the byte. Bits 2-6 are spare in the specification and are kept
    /// in `raw` rather than interpreted.
    pub fn from_raw(raw: u8) -> Self {
        let semantics = match raw & LAYER_SEMANTICS_MASK {
            0 => LayerSemantics::None,
            1 => LayerSemantics::Tombstone,
            2 => LayerSemantics::SupersedeLocal,
            _ => LayerSemantics::SupersedeTree,
        };
        Self {
            semantics,
            inherit_class: raw & INHERIT_CLASS != 0,
            raw,
        }
    }
}

use std::collections::BTreeMap;

use crate::error::{HiveError, Result};
use crate::hive::Hive;
use crate::key_node::KeyNode;
use crate::key_value::KeyValue;
use crate::name::HiveNameString;

/// The most layers a stack may hold: the host plus the 126 "parent" key
/// nodes the specification says Windows stacks at most, as of Windows 10
/// Insider Preview build 15025. A longer chain is not one Windows would
/// present, and refusing it bounds the work a hostile chain can ask for.
pub const MAX_LAYERS: usize = 127;

/// A base hive with differencing hives stacked on it, read as the one
/// registry a container saw.
///
/// Layer 0 is the base; layer *n* is the *n*th differencing hive above it,
/// the last being the most derived. Every [`LayeredKey`] names layers by
/// that index.
pub struct LayeredHive<'a> {
    layers: Vec<Hive<'a>>,
}

impl<'a> LayeredHive<'a> {
    /// Stack `deltas`, in order from the one directly above `base` to the most
    /// derived, over `base`.
    ///
    /// A delta below minor version 6 is refused: it carries no layered-key
    /// bits, so stacking it would treat every one of its keys as a plain merge
    /// and could never honour a deletion it recorded some other way. The base
    /// may be any version — a container's base layer is an ordinary hive.
    pub fn new(base: Hive<'a>, deltas: Vec<Hive<'a>>) -> Result<Self> {
        if deltas.len() + 1 > MAX_LAYERS {
            return Err(HiveError::StructureTooDeep { limit: MAX_LAYERS });
        }
        if let Some(delta) = deltas
            .iter()
            .find(|d| d.minor_version() < LAYERED_MINOR_VERSION)
        {
            return Err(HiveError::Unsupported {
                field: "differencing hive minor version",
                value: delta.minor_version() as u64,
            });
        }
        let mut layers = Vec::with_capacity(deltas.len() + 1);
        layers.push(base);
        layers.extend(deltas);
        Ok(Self { layers })
    }

    /// How many layers, base included.
    pub fn layer_count(&self) -> usize {
        self.layers.len()
    }

    /// The hive at layer `index` (0 is the base).
    pub fn layer(&self, index: usize) -> Option<Hive<'a>> {
        self.layers.get(index).copied()
    }

    /// The merged root key.
    ///
    /// Every layer's root is the same key by construction, so roots are not
    /// matched by name. A root that will not read is an error rather than a
    /// fault: without it that layer contributes nothing, and a merged view
    /// silently missing a whole layer is not one this reader will present.
    pub fn root(&self) -> Result<LayeredKey<'a>> {
        let nodes = self
            .layers
            .iter()
            .map(|hive| hive.root_key_node().map(Some))
            .collect::<Result<Vec<_>>>()?;
        // Only a hostile or mis-ordered chain tombstones its root; say so
        // rather than present an empty registry.
        let root = LayeredKey::from_nodes(nodes, 0).ok_or(HiveError::Unsupported {
            field: "layered root key semantics (tombstoned root)",
            value: LayerSemantics::Tombstone as u64,
        })?;
        // The root is not matched by name, but it is still presented under
        // one: a name that will not read is an error, not an empty string.
        if let Some(node) = root.members.first().and_then(|&l| root.nodes[l]) {
            node.name()?;
        }
        Ok(root)
    }
}

/// How a key's layered-key bits read, with the base's absence of them as `None`.
fn semantics_of(node: &KeyNode<'_>) -> LayerSemantics {
    node.layered_key_bits()
        .map_or(LayerSemantics::None, |bits| bits.semantics)
}

/// Case-insensitive name key: Unicode simple uppercase, one character to one.
fn fold(name: &str) -> String {
    name.chars()
        .map(|c| {
            let mut upper = c.to_uppercase();
            match (upper.next(), upper.next()) {
                (Some(u), None) => u,
                _ => c,
            }
        })
        .collect()
}

/// A key as the merged view presents it.
#[derive(Clone, Debug)]
pub struct LayeredKey<'a> {
    name: String,
    /// This key's node in each layer (index = layer), or `None` where that
    /// layer has none — or is below the floor its ancestors set.
    nodes: Vec<Option<KeyNode<'a>>>,
    /// The layers whose nodes joined the stack, most derived first.
    members: Vec<usize>,
    /// The lowest layer this key's subkeys may be drawn from.
    child_floor: usize,
    /// The lowest layer this key's own stack may draw on (set by ancestors).
    floor: usize,
}

/// What building one key's stack found.
enum Stacked<'a> {
    Present(LayeredKey<'a>),
    /// The most derived node is a tombstone, at this layer.
    Tombstoned(usize),
}

impl<'a> LayeredKey<'a> {
    fn from_nodes(nodes: Vec<Option<KeyNode<'a>>>, floor: usize) -> Option<Self> {
        match Self::stack(nodes, floor) {
            Some(Stacked::Present(key)) => Some(key),
            _ => None,
        }
    }

    /// Build the stack from the most derived layer down to `floor`, by the
    /// rules in the module documentation. `None` when no layer holds a node.
    fn stack(nodes: Vec<Option<KeyNode<'a>>>, floor: usize) -> Option<Stacked<'a>> {
        let mut members = Vec::new();
        let mut child_floor = floor;
        for layer in (floor..nodes.len()).rev() {
            let Some(node) = nodes[layer] else { continue };
            match semantics_of(&node) {
                LayerSemantics::None => members.push(layer),
                LayerSemantics::Tombstone => {
                    if members.is_empty() {
                        return Some(Stacked::Tombstoned(layer));
                    }
                    // Deleted here, re-created above: nothing at or below
                    // this layer is the re-created key's.
                    child_floor = layer + 1;
                    break;
                }
                LayerSemantics::SupersedeLocal => {
                    members.push(layer);
                    break;
                }
                LayerSemantics::SupersedeTree => {
                    members.push(layer);
                    child_floor = layer;
                    break;
                }
            }
        }
        let top = *members.first()?;
        let name = nodes[top]
            .and_then(|n| n.name().ok())
            .map(|n| n.to_string_lossy())
            .unwrap_or_default();
        Some(Stacked::Present(Self {
            name,
            nodes,
            members,
            child_floor,
            floor,
        }))
    }

    /// The key's name, as its most derived node spells it.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The layers whose nodes make up this key, most derived first.
    pub fn contributing_layers(&self) -> &[usize] {
        &self.members
    }

    /// This key's node in `layer`, whether or not that node joined the stack.
    pub fn node_in_layer(&self, layer: usize) -> Option<KeyNode<'a>> {
        self.nodes.get(layer).copied().flatten()
    }

    fn member_nodes(&self) -> impl Iterator<Item = (usize, KeyNode<'a>)> + '_ {
        self.members
            .iter()
            .filter_map(|&layer| self.node_in_layer(layer).map(|node| (layer, node)))
    }

    /// The newest last-written time in the stack.
    pub fn last_written_filetime(&self) -> u64 {
        self.member_nodes()
            .map(|(_, node)| node.last_written_filetime())
            .max()
            .unwrap_or(0)
    }

    /// The class name, by the most derived node in the stack whose *Inherit
    /// class* bit is clear. See [`LayeredClass`] for the three answers, and
    /// why "the key has no class" and "no node in this stack decides it" are
    /// kept apart.
    pub fn class_name(&self) -> LayeredClass<'a> {
        match self
            .member_nodes()
            .find(|(_, node)| !node.layered_key_bits().is_some_and(|b| b.inherit_class))
        {
            Some((layer, node)) => match node.class_name() {
                Some(name) => LayeredClass::Named { layer, name },
                None => LayeredClass::NoClass { layer },
            },
            None => {
                // Every node in the stack says "inherit". That is a fact
                // about the stack only when nothing was cut off below it:
                // with a hidden lower node, or ancestors that cut this key's
                // floor above the base, the class lives where this stack
                // does not reach.
                let lowest = self.members.last().copied().unwrap_or(0);
                let hidden_below = self.nodes[..lowest].iter().any(Option::is_some)
                    || (lowest > 0 && lowest == self.floor);
                if hidden_below {
                    LayeredClass::NotDeterminable
                } else {
                    LayeredClass::NoClass { layer: lowest }
                }
            }
        }
    }

    /// The merged values: the most derived node wins a name.
    pub fn values(&self) -> LayeredValues<'a> {
        let mut out = LayeredValues::default();
        let mut seen = std::collections::HashSet::new();
        for (layer, node) in self.member_nodes() {
            let Some(values) = node.values() else {
                continue;
            };
            let values = match values {
                Ok(values) => values,
                Err(error) => {
                    out.faults.push(LayerFault { layer, error });
                    continue;
                }
            };
            for value in values {
                let value = match value {
                    Ok(value) => value,
                    Err(error) => {
                        out.faults.push(LayerFault { layer, error });
                        continue;
                    }
                };
                let name = match value.name() {
                    Ok(name) => name.to_string_lossy(),
                    Err(error) => {
                        out.faults.push(LayerFault { layer, error });
                        continue;
                    }
                };
                let entry = LayeredValue { layer, name, value };
                if !seen.insert(fold(&entry.name)) {
                    out.shadowed.push(entry);
                } else if node.layered_key_bits().is_some() && entry.value.is_tombstoned() {
                    // Below minor version 6 the `vk` flag is spare, like the
                    // `nk` byte: a stray bit in a base hive is not a deletion.
                    out.tombstoned.push(entry);
                } else {
                    out.values.push(entry);
                }
            }
        }
        out
    }

    /// The merged subkeys, ordered by case-folded name.
    pub fn subkeys(&self) -> LayeredSubkeys<'a> {
        let mut out = LayeredSubkeys::default();
        let layers = self.nodes.len();
        // Folded name -> that child's node in each layer.
        let mut children: BTreeMap<String, Vec<Option<KeyNode<'a>>>> = BTreeMap::new();
        for layer in self.child_floor..layers {
            let Some(node) = self.nodes[layer] else {
                continue;
            };
            let Some(subkeys) = node.subkeys() else {
                continue;
            };
            let subkeys = match subkeys {
                Ok(subkeys) => subkeys,
                Err(error) => {
                    out.faults.push(LayerFault { layer, error });
                    continue;
                }
            };
            for sublist in subkeys.unresolved_sublists() {
                out.faults.push(LayerFault {
                    layer,
                    error: sublist.error.clone(),
                });
            }
            for child in subkeys {
                let child = match child {
                    Ok(child) => child,
                    Err(error) => {
                        out.faults.push(LayerFault { layer, error });
                        continue;
                    }
                };
                let name = match child.name() {
                    Ok(name) => name.to_string_lossy(),
                    Err(error) => {
                        out.faults.push(LayerFault { layer, error });
                        continue;
                    }
                };
                let slot = &mut children
                    .entry(fold(&name))
                    .or_insert_with(|| vec![None; layers])[layer];
                if slot.is_some() {
                    // Windows does not write two siblings whose names fold
                    // equal; a damaged or hostile hive can. The first is
                    // kept and the second reported, never silently swapped
                    // in.
                    out.faults.push(LayerFault {
                        layer,
                        error: HiveError::Unsupported {
                            field: "two subkeys whose names fold equal in one layer",
                            value: layer as u64,
                        },
                    });
                } else {
                    *slot = Some(child);
                }
            }
        }
        for (_, nodes) in children {
            match Self::stack(nodes.clone(), self.child_floor) {
                Some(Stacked::Present(key)) => out.keys.push(key),
                Some(Stacked::Tombstoned(layer)) => out.tombstoned.push(TombstonedKey {
                    name: nodes[layer]
                        .and_then(|n| n.name().ok())
                        .map(|n| n.to_string_lossy())
                        .unwrap_or_default(),
                    layer,
                }),
                None => {}
            }
        }
        out
    }
}

/// A merged key's class name, as [`LayeredKey::class_name`] decides it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LayeredClass<'a> {
    /// The deciding node — the most derived in the stack with *Inherit class*
    /// clear, at `layer` — has a class, decoded or not.
    Named {
        layer: usize,
        name: Result<HiveNameString<'a>>,
    },
    /// The deciding node, at `layer`, has no class: the key has none.
    NoClass { layer: usize },
    /// Every node in the stack has *Inherit class* set, so the class lives in
    /// a layer a supersede or tombstone cut off, and this stack cannot say
    /// what it is. Not the same answer as [`LayeredClass::NoClass`]: the real
    /// Nano Server chain B `SOFTWARE` holds two `SupersedeTree` keys with the
    /// bit set (byte `0x83`), and reading them as classless would claim a fact the
    /// hives do not record.
    NotDeterminable,
}

/// A value in the merged view, and the layer it came from.
#[derive(Clone, Debug)]
pub struct LayeredValue<'a> {
    /// The layer whose node holds this value.
    pub layer: usize,
    /// The value's name, decoded (lossily; see [`HiveNameString`]).
    pub name: String,
    pub value: KeyValue<'a>,
}

/// A layer whose part of the merge could not be read.
///
/// What it named is absent from the merged view and **not** absent from the
/// container: the same contract as [`crate::UnresolvedSublist`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LayerFault {
    pub layer: usize,
    pub error: HiveError,
}

/// A merged key's values, and what the merge hid.
#[derive(Clone, Debug, Default)]
pub struct LayeredValues<'a> {
    /// What the container saw: one value per name.
    pub values: Vec<LayeredValue<'a>>,
    /// Tombstones that are the most derived value of their name: the value
    /// was deleted at that layer and the container did not see it.
    pub tombstoned: Vec<LayeredValue<'a>>,
    /// Values a more derived value (or tombstone) of the same name hid —
    /// what the lower layers held before the change.
    pub shadowed: Vec<LayeredValue<'a>>,
    pub faults: Vec<LayerFault>,
}

/// A subkey the merged view hides because its most derived node is a tombstone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TombstonedKey {
    /// The name as the tombstone spells it.
    pub name: String,
    /// The layer holding the tombstone.
    pub layer: usize,
}

/// A merged key's subkeys, and what the merge hid.
#[derive(Clone, Debug, Default)]
pub struct LayeredSubkeys<'a> {
    pub keys: Vec<LayeredKey<'a>>,
    pub tombstoned: Vec<TombstonedKey>,
    pub faults: Vec<LayerFault>,
}

impl LayeredSubkeys<'_> {
    /// Whether a layer's index would not read, so `keys` may be short.
    pub fn is_incomplete(&self) -> bool {
        !self.faults.is_empty()
    }
}

impl LayeredValues<'_> {
    /// Whether a layer's values would not read, so `values` may be short.
    pub fn is_incomplete(&self) -> bool {
        !self.faults.is_empty()
    }
}
