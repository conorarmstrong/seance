//! [`LayerMeta`]: the facts a layer knows about itself, inherited down a layer
//! chain.
//!
//! Volatility gives every layer a `metadata` mapping that is a `ChainMap` over
//! its dependencies, so a virtual layer built on a crash dump can still see the
//! crash dump's published `DirectoryTableBase`. This reproduces that, with two
//! rules made explicit rather than emergent:
//!
//! - **Identity facts do not inherit.** `format`, `declared_size` and this
//!   layer's own `incomplete` list describe *this* layer. A virtual address
//!   space built over a LiME image is not itself a LiME image.
//! - **Discovered facts do inherit.** `architecture` and free-form `notes`
//!   travel up, because the layer that discovered them is usually not the layer
//!   that needs them.

use seance_core::io::IncompleteReason;
use std::collections::BTreeMap;
use std::sync::Arc;

use crate::format::MemoryImageFormat;

/// The processor architecture an image was captured from.
///
/// Only ever set from something structural: a crash dump's header layout, an
/// ELF core's `e_machine`, a VMCOREINFO note. Never inferred from "it looks
/// like a 64-bit pointer", which is the heuristic that produces a plausible and
/// wrong answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Architecture {
    /// 32-bit x86 (IA-32).
    X86,
    /// 64-bit x86 (AMD64 / Intel 64).
    X64,
    /// 64-bit ARM (AArch64).
    Arm64,
}

impl Architecture {
    /// Stable identifier for artifact metadata.
    pub fn as_str(self) -> &'static str {
        match self {
            Architecture::X86 => "x86",
            Architecture::X64 => "x64",
            Architecture::Arm64 => "arm64",
        }
    }

    /// Width of a guest pointer, in bytes.
    /// The inverse of [`Architecture::as_str`], for metadata that has crossed
    /// the artifact boundary as JSON.
    // Inherent rather than `FromStr`: this answers `Option`, and the trait
    // demands an associated error type that would have to be invented for a
    // name that simply is not one of the variants.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(name: &str) -> Option<Self> {
        Some(match name {
            "x86" => Architecture::X86,
            "x64" => Architecture::X64,
            "arm64" => Architecture::Arm64,
            _ => return None,
        })
    }

    pub fn pointer_size(self) -> u8 {
        match self {
            Architecture::X86 => 4,
            Architecture::X64 | Architecture::Arm64 => 8,
        }
    }
}

/// Something a layer knows it could not fully account for.
///
/// The whole point is that "this really is all there was" and "we stopped
/// early" must never look identical. A layer that hits a cap, a truncated
/// acquisition file or an unreadable structure records it here, and the
/// artifact carries it forward.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Incomplete {
    /// Which class of incompleteness.
    pub reason: IncompleteReason,
    /// What specifically was incomplete, in the examiner's terms.
    pub detail: String,
}

impl Incomplete {
    pub fn new(reason: IncompleteReason, detail: impl Into<String>) -> Self {
        Self {
            reason,
            detail: detail.into(),
        }
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({ "reason": self.reason.as_str(), "detail": self.detail })
    }
}

/// What a layer knows about itself, plus a link to the layer it was built on.
#[derive(Debug, Clone, Default)]
pub struct LayerMeta {
    format: Option<MemoryImageFormat>,
    declared_size: Option<u64>,
    architecture: Option<Architecture>,
    incomplete: Vec<Incomplete>,
    notes: BTreeMap<String, serde_json::Value>,
    parent: Option<Arc<LayerMeta>>,
}

impl LayerMeta {
    /// Metadata for a layer of the given acquisition format.
    pub fn new(format: MemoryImageFormat) -> Self {
        Self {
            format: Some(format),
            ..Self::default()
        }
    }

    /// Attach the metadata of the layer this one was built on. Discovered facts
    /// (`architecture`, notes) are then visible through this layer.
    pub fn with_parent(mut self, parent: Arc<LayerMeta>) -> Self {
        self.parent = Some(parent);
        self
    }

    /// Record the size the image's own structures declare, which is not always
    /// the size of the file holding them: a truncated acquisition declares more
    /// than it contains, and that discrepancy is evidence.
    pub fn with_declared_size(mut self, size: u64) -> Self {
        self.declared_size = Some(size);
        self
    }

    /// Record a structurally determined architecture. Callers that are guessing
    /// must not call this.
    pub fn with_architecture(mut self, arch: Architecture) -> Self {
        self.architecture = Some(arch);
        self
    }

    /// Record something this layer could not fully account for.
    pub fn with_incomplete(mut self, reason: IncompleteReason, detail: impl Into<String>) -> Self {
        self.incomplete.push(Incomplete::new(reason, detail));
        self
    }

    /// Publish a format-specific fact for layers above: a crash dump's
    /// `DirectoryTableBase`, a QEMU machine type, a VMware region count.
    pub fn with_note(
        mut self,
        key: impl Into<String>,
        value: impl Into<serde_json::Value>,
    ) -> Self {
        self.notes.insert(key.into(), value.into());
        self
    }

    /// Same as [`LayerMeta::with_incomplete`], for use after construction.
    pub fn push_incomplete(&mut self, reason: IncompleteReason, detail: impl Into<String>) {
        self.incomplete.push(Incomplete::new(reason, detail));
    }

    /// This layer's acquisition format. Does not inherit: a virtual address
    /// space over a LiME image is not a LiME image.
    pub fn format(&self) -> Option<MemoryImageFormat> {
        self.format
    }

    /// The size this layer's own structures declare, if any. Does not inherit.
    pub fn declared_size(&self) -> Option<u64> {
        self.declared_size
    }

    /// The architecture, from this layer or the nearest ancestor that knows it.
    pub fn architecture(&self) -> Option<Architecture> {
        let mut cursor = Some(self);
        while let Some(meta) = cursor {
            if let Some(arch) = meta.architecture {
                return Some(arch);
            }
            cursor = meta.parent.as_deref();
        }
        None
    }

    /// A published fact, from this layer or the nearest ancestor that has it.
    /// Nearest wins, so a layer can override what it was built on.
    pub fn note(&self, key: &str) -> Option<&serde_json::Value> {
        let mut cursor = Some(self);
        while let Some(meta) = cursor {
            if let Some(value) = meta.notes.get(key) {
                return Some(value);
            }
            cursor = meta.parent.as_deref();
        }
        None
    }

    /// Only this layer's own incompleteness.
    pub fn incomplete(&self) -> &[Incomplete] {
        &self.incomplete
    }

    /// Every incompleteness in the chain, this layer first then upward. A
    /// truncation two layers down still makes everything above it incomplete,
    /// and the examiner needs the whole list, not the top one.
    pub fn incomplete_chain(&self) -> Vec<Incomplete> {
        let mut out = Vec::new();
        let mut cursor = Some(self);
        while let Some(meta) = cursor {
            out.extend(meta.incomplete.iter().cloned());
            cursor = meta.parent.as_deref();
        }
        out
    }

    /// The metadata of the layer this one was built on.
    pub fn parent(&self) -> Option<&LayerMeta> {
        self.parent.as_deref()
    }

    /// How many layers there are from here to the bottom of the chain,
    /// counting this one.
    pub fn chain_depth(&self) -> usize {
        let mut depth = 0usize;
        let mut cursor = Some(self);
        while let Some(meta) = cursor {
            depth += 1;
            cursor = meta.parent.as_deref();
        }
        depth
    }

    /// The chain-resolved view, ready to drop into artifact metadata.
    ///
    /// Inherited values appear resolved; `incomplete` is the whole chain, so a
    /// consumer cannot read this and believe the evidence was complete.
    pub fn to_json(&self) -> serde_json::Value {
        let mut notes = serde_json::Map::new();
        // Walk from the bottom of the chain upward so nearer layers overwrite
        // what they inherited.
        let mut chain: Vec<&LayerMeta> = Vec::new();
        let mut cursor = Some(self);
        while let Some(meta) = cursor {
            chain.push(meta);
            cursor = meta.parent.as_deref();
        }
        for meta in chain.iter().rev() {
            for (key, value) in &meta.notes {
                notes.insert(key.clone(), value.clone());
            }
        }

        let incomplete: Vec<serde_json::Value> = self
            .incomplete_chain()
            .iter()
            .map(|i| i.to_json())
            .collect();

        serde_json::json!({
            "format": self.format.map(|f| f.as_str()),
            "declared_size": self.declared_size,
            "architecture": self.architecture().map(|a| a.as_str()),
            "chain_depth": self.chain_depth(),
            "incomplete": incomplete,
            "notes": serde_json::Value::Object(notes),
        })
    }

    /// Rebuild a flattened `LayerMeta` from what [`LayerMeta::to_json`] wrote.
    ///
    /// An artifact carries its data as a `DataSource`, which is the right thing
    /// for every other module in the tree but loses everything a memory layer
    /// knows about itself. Reopening that source produces a blank
    /// `LayerMeta::new(Raw)`, and with it goes the format, the acquisition's own
    /// statement of its incompleteness, and every note — including the
    /// directory table base and `KdDebuggerDataBlock` a Windows crash dump
    /// publishes in its header.
    ///
    /// Discovery reads those notes. Losing them does not fail loudly; it
    /// silently demotes a crash dump whose header states the DTB to an image
    /// that has to be scanned for one, which is slower and can pick a different
    /// answer. So the meta is serialised onto the artifact and restored here,
    /// crossing the boundary as data rather than as a live object.
    ///
    /// The chain is flattened: what comes back is one `LayerMeta` carrying the
    /// notes and incompleteness the whole chain contributed, which is what a
    /// consumer reads anyway. `chain_depth` is not restored, because the layers
    /// it counted no longer exist on this side of the boundary.
    pub fn from_json(value: &serde_json::Value) -> Self {
        let mut meta = LayerMeta {
            format: value
                .get("format")
                .and_then(|f| f.as_str())
                .and_then(crate::format::MemoryImageFormat::from_str),
            declared_size: value.get("declared_size").and_then(|d| d.as_u64()),
            architecture: value
                .get("architecture")
                .and_then(|a| a.as_str())
                .and_then(Architecture::from_str),
            incomplete: Vec::new(),
            notes: BTreeMap::new(),
            parent: None,
        };
        if let Some(items) = value.get("incomplete").and_then(|i| i.as_array()) {
            for item in items {
                let reason = item
                    .get("reason")
                    .and_then(|r| r.as_str())
                    .and_then(IncompleteReason::from_str)
                    .unwrap_or(IncompleteReason::ShortRead);
                let detail = item
                    .get("detail")
                    .and_then(|d| d.as_str())
                    .unwrap_or_default()
                    .to_string();
                meta.incomplete.push(Incomplete { reason, detail });
            }
        }
        if let Some(notes) = value.get("notes").and_then(|n| n.as_object()) {
            for (key, note) in notes {
                meta.notes.insert(key.clone(), note.clone());
            }
        }
        meta
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn architecture_widths_are_correct() {
        assert_eq!(Architecture::X86.pointer_size(), 4);
        assert_eq!(Architecture::X64.pointer_size(), 8);
        assert_eq!(Architecture::Arm64.pointer_size(), 8);
        assert_eq!(Architecture::Arm64.as_str(), "arm64");
    }

    #[test]
    fn identity_facts_do_not_inherit() {
        let base = Arc::new(
            LayerMeta::new(MemoryImageFormat::Lime)
                .with_declared_size(0x8000_0000)
                .with_architecture(Architecture::X64),
        );
        // A virtual address space over a LiME image is not a LiME image, and
        // does not declare the LiME image's size.
        let upper = LayerMeta::default().with_parent(base.clone());
        assert_eq!(upper.format(), None);
        assert_eq!(upper.declared_size(), None);
        assert_eq!(base.format(), Some(MemoryImageFormat::Lime));
        assert_eq!(base.declared_size(), Some(0x8000_0000));
    }

    #[test]
    fn discovered_facts_inherit_up_the_chain() {
        let base = Arc::new(
            LayerMeta::new(MemoryImageFormat::WindowsCrashDump64)
                .with_architecture(Architecture::X64)
                .with_note("directory_table_base", 0x1a_b000u64),
        );
        let middle = Arc::new(LayerMeta::default().with_parent(base));
        let top = LayerMeta::default().with_parent(middle);

        assert_eq!(top.architecture(), Some(Architecture::X64));
        assert_eq!(
            top.note("directory_table_base"),
            Some(&serde_json::json!(0x1a_b000u64))
        );
        assert_eq!(top.note("nonexistent"), None);
        assert_eq!(top.chain_depth(), 3);
    }

    #[test]
    fn a_nearer_layer_overrides_what_it_inherited() {
        let base = Arc::new(
            LayerMeta::new(MemoryImageFormat::Raw)
                .with_architecture(Architecture::X86)
                .with_note("dtb_source", "container"),
        );
        let upper = LayerMeta::default()
            .with_parent(base)
            .with_architecture(Architecture::X64)
            .with_note("dtb_source", "self_referential_scan");

        assert_eq!(upper.architecture(), Some(Architecture::X64));
        assert_eq!(
            upper.note("dtb_source"),
            Some(&serde_json::json!("self_referential_scan"))
        );
    }

    #[test]
    fn incompleteness_is_collected_across_the_whole_chain() {
        let base = Arc::new(
            LayerMeta::new(MemoryImageFormat::Lime)
                .with_incomplete(IncompleteReason::ShortRead, "acquisition file truncated"),
        );
        let mut upper = LayerMeta::default().with_parent(base);
        upper.push_incomplete(IncompleteReason::CapReached, "segment cap reached");

        assert_eq!(upper.incomplete().len(), 1, "own list stays own");
        let chain = upper.incomplete_chain();
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[0].reason, IncompleteReason::CapReached);
        assert_eq!(chain[1].reason, IncompleteReason::ShortRead);
        assert_eq!(chain[1].detail, "acquisition file truncated");
    }

    #[test]
    fn json_view_resolves_the_chain_without_hiding_incompleteness() {
        let base = Arc::new(
            LayerMeta::new(MemoryImageFormat::WindowsCrashDump64)
                .with_architecture(Architecture::X64)
                .with_note("dump_type", 1u64)
                .with_incomplete(IncompleteReason::ShortRead, "run 4 past end of file"),
        );
        let top = LayerMeta::default()
            .with_parent(base)
            .with_note("uniform_tables_suppressed", 1483u64);

        let json = top.to_json();
        assert_eq!(json["architecture"], "x64");
        assert_eq!(json["format"], serde_json::Value::Null);
        assert_eq!(json["chain_depth"], 2);
        assert_eq!(json["notes"]["dump_type"], 1);
        assert_eq!(json["notes"]["uniform_tables_suppressed"], 1483);
        let incomplete = json["incomplete"].as_array().expect("array");
        assert_eq!(incomplete.len(), 1);
        assert_eq!(incomplete[0]["reason"], "short_read");
        assert_eq!(incomplete[0]["detail"], "run 4 past end of file");
    }

    #[test]
    fn a_bare_layer_reports_nothing_it_does_not_know() {
        let meta = LayerMeta::default();
        assert_eq!(meta.format(), None);
        assert_eq!(meta.architecture(), None);
        assert_eq!(meta.declared_size(), None);
        assert!(meta.incomplete_chain().is_empty());
        assert_eq!(meta.chain_depth(), 1);
        assert!(meta.parent().is_none());
        assert_eq!(meta.to_json()["architecture"], serde_json::Value::Null);
    }
}
