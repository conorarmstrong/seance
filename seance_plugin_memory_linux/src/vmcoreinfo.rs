//! The kernel's `VMCOREINFO` text, read out of physical memory.
//!
//! Every kernel built with `CONFIG_CRASH_CORE` (kdump support — every
//! distribution kernel) keeps a page of `KEY=VALUE` lines describing itself
//! for a crash tool: its release, its page size, the addresses of a handful
//! of symbols, and per-architecture numbers. Two copies normally sit in RAM:
//! the `vmcoreinfo_data` buffer and the ELF note the kernel publishes to a
//! kdump kernel (the same text after a `VMCOREINFO` note name). Both begin
//! with `OSRELEASE=`.
//!
//! ```text
//! OSRELEASE=4.19.0-11-arm64
//! PAGESIZE=4096
//! SYMBOL(init_uts_ns)=ffff0000090e2c68        <- hex, no prefix (%lx)
//! SYMBOL(swapper_pg_dir)=ffff0000092ee000
//! OFFSET(list_head.next)=0                    <- decimal
//! NUMBER(VA_BITS)=48                          <- decimal (%ld) ...
//! NUMBER(kimage_voffset)=0xfffeffffc8000000   <- ... or 0x-hex (arm64's own lines)
//! KERNELOFFSET=0                              <- hex, no prefix
//! ```
//!
//! # What it is used for here
//!
//! On arm64 it is the one place the image states where the kernel's page
//! tables are: `swapper_pg_dir` is a kernel-image virtual address, and
//! `kimage_voffset` is the kernel image's virtual-to-physical offset, so their
//! difference is the physical root `TTBR1_EL1` held. That is still a claim the
//! image makes about itself; [`prove_arm64_kernel_root`] turns it into a fact
//! by walking the tables from that root and requiring `init_uts_ns` to read
//! back the release the note declared, and it names every regime it tried.
//!
//! It is also the architecture hint discovery's refusal uses: a note with
//! `NUMBER(kimage_voffset)` was written by an arm64 kernel.
//!
//! # What it does not do
//!
//! It never stands in for a symbol table. The note names a dozen symbols and
//! a few dozen member offsets chosen for `makedumpfile`; no analysis stage
//! can run from it, and nothing here offers one.

use std::collections::BTreeMap;
use std::sync::Arc;

use seance_memory::layer::MemoryLayer;
use seance_memory::scan::{scan_layer, ScanConfig, SingleStringScanner};
use seance_memory::translate::{
    Arm64Granule, Arm64Regime, PagingMode, PagingSpec, PteSemantics, Ttbr, VirtualLayer,
};

/// Every `VMCOREINFO` text begins with this line.
pub const VMCOREINFO_NEEDLE: &[u8] = b"OSRELEASE=";

/// The most bytes one note can hold: the kernel allocates `VMCOREINFO_BYTES`,
/// one page, and so reading more after a needle would let the evidence decide
/// how much memory to allocate.
pub const MAX_VMCOREINFO_BYTES: usize = 4096;

/// How many `OSRELEASE=` hits a sweep examines. A kernel holds two copies and
/// its own `.rodata` holds the format string; the rest are stale pages.
pub const MAX_VMCOREINFO_HITS: usize = 64;

/// Which architecture's kernel wrote a note, from lines only that
/// architecture's `arch_crash_save_vmcoreinfo` emits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmcoreArchitecture {
    /// `NUMBER(kimage_voffset)` (arch/arm64/kernel/crash_core.c).
    Arm64,
    /// `NUMBER(phys_base)` or `SYMBOL(init_top_pgt)` / `SYMBOL(init_level4_pgt)`
    /// (arch/x86/kernel/machine_kexec_64.c).
    X86_64,
    /// Nothing architecture-specific is in the note.
    Unknown,
}

impl VmcoreArchitecture {
    /// Stable identifier for metadata and messages.
    pub fn as_str(self) -> &'static str {
        match self {
            VmcoreArchitecture::Arm64 => "arm64",
            VmcoreArchitecture::X86_64 => "x86_64",
            VmcoreArchitecture::Unknown => "unknown",
        }
    }
}

/// One parsed `VMCOREINFO` text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmcoreInfo {
    osrelease: String,
    /// Every `KEY=VALUE` line, key as written (`SYMBOL(init_uts_ns)`), value
    /// verbatim.
    entries: BTreeMap<String, String>,
}

/// Why bytes that begin like a note are not one this reader will state.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VmcoreInfoError {
    /// The bytes do not begin with an `OSRELEASE=` line naming a release — the
    /// kernel's own `"OSRELEASE=%s"` format string, a fragment, noise.
    #[error("the bytes are not a VMCOREINFO text: {0}")]
    NotVmcoreinfo(&'static str),
    /// The text runs to the end of the window, or its last line is cut off.
    #[error(
        "the VMCOREINFO text is truncated ({0}); a note whose end was not seen may have lost \
         the lines that matter, so none of it is stated"
    )]
    Truncated(&'static str),
    /// A line is not `KEY=VALUE`, or a value is not in the form its key takes.
    #[error("the VMCOREINFO line '{line}' is malformed: {detail}")]
    Malformed { line: String, detail: &'static str },
    /// One key appears twice with different values.
    #[error(
        "the VMCOREINFO text states '{key}' twice and disagrees with itself ('{first}' and \
         '{second}'), so neither value is stated"
    )]
    Conflicting {
        key: String,
        first: String,
        second: String,
    },
    /// The sweep did not examine every mapped byte or return every hit, so
    /// whether a copy exists — or whether an unseen copy contradicts the ones
    /// found — could not be looked at.
    #[error(
        "the VMCOREINFO sweep was cut short ({found} copy/copies found before it stopped), so \
         whether the image holds a note, or one that contradicts those found, could not be \
         looked at"
    )]
    SweepIncomplete { found: usize },
}

impl VmcoreInfo {
    /// Parse one note from the bytes at a needle hit.
    ///
    /// The text ends at the first NUL, which must fall inside
    /// [`MAX_VMCOREINFO_BYTES`], and every line before it must be a complete
    /// `KEY=VALUE` line ending in a newline, as the kernel writes them.
    /// Values are checked against the form their key takes (`SYMBOL(..)` and
    /// `KERNELOFFSET` hex without a prefix; `SIZE`, `OFFSET`, `LENGTH` and
    /// `PAGESIZE` decimal; `NUMBER(..)` decimal or `0x`-hex), which is what
    /// rejects the format strings in the kernel's `.rodata`.
    pub fn parse(bytes: &[u8]) -> Result<Self, VmcoreInfoError> {
        if !bytes.starts_with(VMCOREINFO_NEEDLE) {
            return Err(VmcoreInfoError::NotVmcoreinfo(
                "it does not begin with an OSRELEASE= line",
            ));
        }
        let window = &bytes[..bytes.len().min(MAX_VMCOREINFO_BYTES)];
        let Some(end) = window.iter().position(|&b| b == 0) else {
            return Err(VmcoreInfoError::Truncated(
                if bytes.len() >= MAX_VMCOREINFO_BYTES {
                    "no terminator within one page"
                } else {
                    "the image ends before the text does"
                },
            ));
        };
        let text = &window[..end];
        let mut lines = text.split(|&b| b == b'\n');
        let first = lines.next().unwrap_or_default();
        let osrelease = &first[VMCOREINFO_NEEDLE.len()..];
        if osrelease.is_empty()
            || osrelease.contains(&b'%')
            || !osrelease.iter().all(u8::is_ascii_graphic)
        {
            return Err(VmcoreInfoError::NotVmcoreinfo(
                "its OSRELEASE= line names no release (a format string or a fragment)",
            ));
        }
        if !text.ends_with(b"\n") {
            return Err(VmcoreInfoError::Truncated("the last line is cut off"));
        }
        let osrelease = String::from_utf8_lossy(osrelease).into_owned();
        let mut entries: BTreeMap<String, String> = BTreeMap::new();
        entries.insert("OSRELEASE".to_string(), osrelease.clone());
        for line in lines {
            if line.is_empty() {
                // The empty string after the final newline.
                continue;
            }
            let rendered = String::from_utf8_lossy(line).into_owned();
            let malformed = |detail| VmcoreInfoError::Malformed {
                line: rendered.clone(),
                detail,
            };
            let Some(eq) = line.iter().position(|&b| b == b'=') else {
                return Err(malformed("it is not KEY=VALUE"));
            };
            let (key, value) = (&line[..eq], &line[eq + 1..]);
            if key.is_empty() || !key.iter().all(u8::is_ascii_graphic) {
                return Err(malformed("the key is empty or not printable"));
            }
            if !value.iter().all(|b| (0x20..0x7f).contains(b)) {
                return Err(malformed("the value is not printable text"));
            }
            let key = String::from_utf8_lossy(key).into_owned();
            let value = String::from_utf8_lossy(value).into_owned();
            if let Some(detail) = form_violation(&key, &value) {
                return Err(malformed(detail));
            }
            match entries.get(&key) {
                Some(existing) if *existing != value => {
                    return Err(VmcoreInfoError::Conflicting {
                        key,
                        first: existing.clone(),
                        second: value,
                    });
                }
                Some(_) => {}
                None => {
                    entries.insert(key, value);
                }
            }
        }
        Ok(Self { osrelease, entries })
    }

    /// `OSRELEASE`, the kernel release (`uname -r`).
    pub fn osrelease(&self) -> &str {
        &self.osrelease
    }

    /// A line's value verbatim.
    pub fn raw(&self, key: &str) -> Option<&str> {
        self.entries.get(key).map(String::as_str)
    }

    /// Every line, in key order.
    pub fn entries(&self) -> &BTreeMap<String, String> {
        &self.entries
    }

    /// `PAGESIZE`.
    pub fn page_size(&self) -> Option<u64> {
        self.raw("PAGESIZE")?.parse().ok()
    }

    /// `SYMBOL(name)`: a kernel virtual address.
    pub fn symbol(&self, name: &str) -> Option<u64> {
        u64::from_str_radix(self.raw(&format!("SYMBOL({name})"))?, 16).ok()
    }

    /// `NUMBER(name)` as an unsigned value. `None` for a negative number
    /// (`PAGE_BUDDY_MAPCOUNT_VALUE` is one); [`VmcoreInfo::raw`] has it.
    pub fn number(&self, name: &str) -> Option<u64> {
        let raw = self.raw(&format!("NUMBER({name})"))?;
        match raw.strip_prefix("0x") {
            Some(hex) => u64::from_str_radix(hex, 16).ok(),
            None => raw.parse().ok(),
        }
    }

    /// Which architecture's kernel wrote this note.
    pub fn architecture(&self) -> VmcoreArchitecture {
        if self.entries.contains_key("NUMBER(kimage_voffset)") {
            VmcoreArchitecture::Arm64
        } else if [
            "NUMBER(phys_base)",
            "SYMBOL(init_top_pgt)",
            "SYMBOL(init_level4_pgt)",
        ]
        .iter()
        .any(|key| self.entries.contains_key(*key))
        {
            VmcoreArchitecture::X86_64
        } else {
            VmcoreArchitecture::Unknown
        }
    }

    /// The physical address of the arm64 kernel's top-level page table:
    /// `SYMBOL(swapper_pg_dir) - NUMBER(kimage_voffset)`. A claim, not a
    /// proof — see [`prove_arm64_kernel_root`].
    pub fn arm64_kernel_root(&self) -> Option<u64> {
        if self.architecture() != VmcoreArchitecture::Arm64 {
            return None;
        }
        self.symbol("swapper_pg_dir")?
            .checked_sub(self.number("kimage_voffset")?)
    }
}

/// Whether `value` is in the form `key` takes, and if not, why.
fn form_violation(key: &str, value: &str) -> Option<&'static str> {
    fn hex(v: &str) -> bool {
        !v.is_empty() && v.len() <= 16 && v.bytes().all(|b| b.is_ascii_hexdigit())
    }
    fn decimal(v: &str) -> bool {
        let digits = v.strip_prefix('-').unwrap_or(v);
        !digits.is_empty() && digits.len() <= 20 && digits.bytes().all(|b| b.is_ascii_digit())
    }
    let bracketed = |prefix: &str| key.starts_with(prefix) && key.ends_with(')');
    if bracketed("SYMBOL(") || key == "KERNELOFFSET" {
        (!hex(value)).then_some("the value is not hexadecimal without a prefix")
    } else if bracketed("SIZE(") || bracketed("OFFSET(") || bracketed("LENGTH(") {
        (!decimal(value)).then_some("the value is not a decimal number")
    } else if key == "PAGESIZE" {
        (!(decimal(value) && !value.starts_with('-')))
            .then_some("the value is not a positive decimal number")
    } else if bracketed("NUMBER(") {
        let ok = match value.strip_prefix("0x") {
            Some(digits) => hex(digits),
            None => decimal(value),
        };
        (!ok).then_some("the value is neither decimal nor 0x-hexadecimal")
    } else if key == "OSRELEASE" {
        Some("OSRELEASE is stated on a line other than the first")
    } else {
        None
    }
}

/// Every note a physical sweep found, and every hit that was not one.
#[derive(Debug, Clone, Default)]
pub struct VmcoreSweep {
    /// Notes that parsed, with the physical address each began at.
    pub found: Vec<(u64, VmcoreInfo)>,
    /// Hits that were refused, with why.
    pub refused: Vec<(u64, VmcoreInfoError)>,
    /// Whether every mapped byte was examined and every hit returned.
    pub complete: bool,
}

impl VmcoreSweep {
    /// The note the image states, when every copy found agrees.
    ///
    /// `Ok(None)` only when a complete sweep found no copy; an error naming
    /// the first two copies that disagree, because picking one of two
    /// contradictory notes would be a choice nothing in the image justifies;
    /// and [`VmcoreInfoError::SweepIncomplete`] when the sweep was cut short
    /// and the copies found do not contradict each other — an absence it
    /// could not look for is not an absence, and an unseen copy could
    /// contradict the ones it did see.
    pub fn agreed(&self) -> Result<Option<&VmcoreInfo>, VmcoreInfoError> {
        let incomplete = VmcoreInfoError::SweepIncomplete {
            found: self.found.len(),
        };
        let Some((_, first)) = self.found.first() else {
            return if self.complete {
                Ok(None)
            } else {
                Err(incomplete)
            };
        };
        for (_, other) in &self.found[1..] {
            if other == first {
                continue;
            }
            let keys = first.entries.keys().chain(other.entries.keys());
            for key in keys {
                let (a, b) = (first.raw(key), other.raw(key));
                if a != b {
                    return Err(VmcoreInfoError::Conflicting {
                        key: key.clone(),
                        first: a.unwrap_or("(absent)").to_string(),
                        second: b.unwrap_or("(absent)").to_string(),
                    });
                }
            }
        }
        if !self.complete {
            return Err(incomplete);
        }
        Ok(Some(first))
    }
}

/// Sweep physical memory for `VMCOREINFO` notes.
pub fn sweep(physical: &dyn MemoryLayer) -> Result<VmcoreSweep, String> {
    let scanner =
        SingleStringScanner::new("vmcoreinfo", VMCOREINFO_NEEDLE).map_err(|e| e.to_string())?;
    let config = ScanConfig {
        max_hits: MAX_VMCOREINFO_HITS,
        ..ScanConfig::default()
    };
    let outcome = scan_layer(physical, &scanner, &config).map_err(|e| e.to_string())?;
    let mut sweep = VmcoreSweep {
        complete: outcome.is_complete(),
        ..VmcoreSweep::default()
    };
    for hit in &outcome.hits {
        let mut buf = vec![0u8; MAX_VMCOREINFO_BYTES];
        let read = seance_core::io::read_full(physical.as_data_source(), hit.address, &mut buf);
        buf.truncate(read);
        match VmcoreInfo::parse(&buf) {
            Ok(info) => sweep.found.push((hit.address, info)),
            Err(err) => sweep.refused.push((hit.address, err)),
        }
    }
    Ok(sweep)
}

/// The arm64 kernel regimes (granule, VA width) the root proof offers, most
/// common first: the `ARM64_VA_BITS` choices `arch/arm64/Kconfig` gives each
/// page size, without the 52-bit ones (FEAT_LPA2 / FEAT_LVA, refused).
pub const ARM64_KERNEL_REGIMES: [(Arm64Granule, u8); 7] = [
    (Arm64Granule::Kb4, 48),
    (Arm64Granule::Kb4, 39),
    (Arm64Granule::Kb64, 48),
    (Arm64Granule::Kb64, 42),
    (Arm64Granule::Kb16, 47),
    (Arm64Granule::Kb16, 48),
    (Arm64Granule::Kb16, 36),
];

/// `struct uts_namespace` begins with a `kref` and then `struct
/// new_utsname`, six 65-byte strings. The release is looked for inside this
/// span, NUL-terminated, rather than at a fixed offset the build decides.
const UTS_NAMESPACE_SPAN: usize = 4 + 6 * 65 + 64;

/// An arm64 kernel page-table root proved by using it.
pub struct Arm64RootProof {
    /// The physical root.
    pub root: u64,
    /// The one regime under which the proof held.
    pub regime: Arm64Regime,
    /// The kernel's address space under that regime.
    pub space: VirtualLayer,
    /// Every regime tried, named, for the record.
    pub tried: Vec<String>,
}

/// Why an arm64 root could not be proved from a note.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Arm64RootRefusal {
    /// The note is not an arm64 kernel's, or lacks a line the proof needs.
    #[error("the VMCOREINFO note cannot anchor an arm64 root proof: {0}")]
    NoteInsufficient(&'static str),
    /// No offered regime translated `init_uts_ns` to the declared release.
    #[error(
        "no arm64 regime ({tried}) translates SYMBOL(init_uts_ns) {anchor:#x} through the root \
         {root:#x} to bytes holding the release '{release}', so the root is not proved"
    )]
    NoRegimeProves {
        root: u64,
        anchor: u64,
        release: String,
        tried: String,
    },
    /// More than one regime proved, and nothing says which the machine used.
    #[error("more than one arm64 regime proves the root {root:#x} ({proved}); none is chosen")]
    Ambiguous { root: u64, proved: String },
    /// The regime that proved is not the one the note declares.
    #[error(
        "the regime that proves the root ({proved}) is not the one the note declares \
         (PAGESIZE {page_size}, VA_BITS {va_bits}); neither is chosen"
    )]
    DisagreesWithNote {
        proved: String,
        page_size: u64,
        va_bits: u64,
    },
}

/// Prove the arm64 kernel page-table root a note states.
///
/// The root is [`VmcoreInfo::arm64_kernel_root`]. Each regime in
/// [`ARM64_KERNEL_REGIMES`] is walked from it under TTBR1 rules; a regime
/// proves when `SYMBOL(init_uts_ns)` translates and the bytes there hold the
/// note's `OSRELEASE`, NUL-terminated. Exactly one regime must prove, and it
/// must agree with the note's `PAGESIZE` and `NUMBER(VA_BITS)` where the note
/// states them.
pub fn prove_arm64_kernel_root(
    physical: &Arc<dyn MemoryLayer>,
    info: &VmcoreInfo,
) -> Result<Arm64RootProof, Arm64RootRefusal> {
    if info.architecture() != VmcoreArchitecture::Arm64 {
        return Err(Arm64RootRefusal::NoteInsufficient(
            "it is not an arm64 kernel's (no NUMBER(kimage_voffset))",
        ));
    }
    let root = info
        .arm64_kernel_root()
        .ok_or(Arm64RootRefusal::NoteInsufficient(
            "it states no SYMBOL(swapper_pg_dir), or one below NUMBER(kimage_voffset)",
        ))?;
    let anchor = info
        .symbol("init_uts_ns")
        .ok_or(Arm64RootRefusal::NoteInsufficient(
            "it states no SYMBOL(init_uts_ns) to read the release back from",
        ))?;
    let mut expected = info.osrelease().as_bytes().to_vec();
    expected.push(0);

    let mut tried = Vec::new();
    let mut proved: Vec<(Arm64Regime, VirtualLayer)> = Vec::new();
    for (granule, va_bits) in ARM64_KERNEL_REGIMES {
        let Ok(regime) = Arm64Regime::new(granule, Ttbr::Ttbr1, va_bits) else {
            continue;
        };
        let mode = PagingMode::Arm64(regime);
        tried.push(mode.to_string());
        let spec = PagingSpec::new(mode, PteSemantics::Linux);
        let Ok(space) = VirtualLayer::new(Arc::clone(physical), root, spec) else {
            continue;
        };
        if space.translate(anchor).is_err() {
            continue;
        }
        let mut buf = vec![0u8; UTS_NAMESPACE_SPAN];
        let read = seance_core::io::read_full(space.as_data_source(), anchor, &mut buf);
        buf.truncate(read);
        if buf
            .windows(expected.len())
            .any(|w| w == expected.as_slice())
        {
            proved.push((regime, space));
        }
    }
    let named = |list: &[(Arm64Regime, VirtualLayer)]| {
        list.iter()
            .map(|(regime, _)| PagingMode::Arm64(*regime).to_string())
            .collect::<Vec<_>>()
            .join(", ")
    };
    if proved.len() > 1 {
        return Err(Arm64RootRefusal::Ambiguous {
            root,
            proved: named(&proved),
        });
    }
    let Some((regime, space)) = proved.pop() else {
        return Err(Arm64RootRefusal::NoRegimeProves {
            root,
            anchor,
            release: info.osrelease().to_string(),
            tried: tried.join(", "),
        });
    };
    let page_size = info.page_size();
    let va_bits = info.number("VA_BITS");
    let page_agrees = page_size.is_none_or(|p| p == 1u64 << regime.granule().page_shift());
    let bits_agree = va_bits.is_none_or(|v| v == u64::from(regime.va_bits()));
    if !(page_agrees && bits_agree) {
        return Err(Arm64RootRefusal::DisagreesWithNote {
            proved: PagingMode::Arm64(regime).to_string(),
            page_size: page_size.unwrap_or(0),
            va_bits: va_bits.unwrap_or(0),
        });
    }
    Ok(Arm64RootProof {
        root,
        regime,
        space,
        tried,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The head and the arm64 tail of the note found in the MMUShell
    /// `aarch64/linux_debian` dump (QEMU-emulated), quoted verbatim; the
    /// middle lines are elided but each form is represented.
    const DEBIAN_ARM64: &str = "OSRELEASE=4.19.0-11-arm64\n\
PAGESIZE=4096\n\
SYMBOL(init_uts_ns)=ffff0000090e2c68\n\
SYMBOL(node_online_map)=ffff0000090dab80\n\
SYMBOL(swapper_pg_dir)=ffff0000092ee000\n\
SYMBOL(_stext)=ffff000008081000\n\
LENGTH(mem_section)=2048\n\
SIZE(page)=64\n\
OFFSET(list_head.next)=0\n\
OFFSET(list_head.prev)=8\n\
NUMBER(PG_head_mask)=32768\n\
NUMBER(PAGE_BUDDY_MAPCOUNT_VALUE)=-129\n\
NUMBER(VA_BITS)=48\n\
NUMBER(kimage_voffset)=0xfffeffffc8000000\n\
NUMBER(PHYS_OFFSET)=0x40000000\n\
KERNELOFFSET=0\n";

    fn note(text: &str) -> Vec<u8> {
        let mut bytes = text.as_bytes().to_vec();
        bytes.extend_from_slice(&[0u8; 64]);
        bytes
    }

    #[test]
    fn vmcoreinfo_parses_symbols_numbers_and_osrelease() {
        let info = VmcoreInfo::parse(&note(DEBIAN_ARM64)).expect("a real note");
        assert_eq!(info.osrelease(), "4.19.0-11-arm64");
        assert_eq!(info.page_size(), Some(4096));
        assert_eq!(info.symbol("init_uts_ns"), Some(0xffff_0000_090e_2c68));
        assert_eq!(info.symbol("swapper_pg_dir"), Some(0xffff_0000_092e_e000));
        assert_eq!(info.number("VA_BITS"), Some(48));
        assert_eq!(info.number("kimage_voffset"), Some(0xfffe_ffff_c800_0000));
        assert_eq!(info.number("PHYS_OFFSET"), Some(0x4000_0000));
        assert_eq!(info.number("PAGE_BUDDY_MAPCOUNT_VALUE"), None, "negative");
        assert_eq!(info.raw("NUMBER(PAGE_BUDDY_MAPCOUNT_VALUE)"), Some("-129"));
        assert_eq!(info.raw("KERNELOFFSET"), Some("0"));
        assert_eq!(info.symbol("init_task"), None, "not in the note");
    }

    #[test]
    fn an_arm64_vmcoreinfo_is_recognised_by_kimage_voffset() {
        let info = VmcoreInfo::parse(&note(DEBIAN_ARM64)).unwrap();
        assert_eq!(info.architecture(), VmcoreArchitecture::Arm64);
        // swapper_pg_dir - kimage_voffset:
        //   0xffff_0000_092e_e000 - 0xfffe_ffff_c800_0000 = 0x412e_e000,
        // the BADDR of the TTBR1_EL1 QEMU recorded (0x42e_0000_412e_e000).
        assert_eq!(info.arm64_kernel_root(), Some(0x412e_e000));

        let x86 = "OSRELEASE=5.15.0-91-generic\nPAGESIZE=4096\n\
SYMBOL(init_top_pgt)=ffffffff9ce10000\nNUMBER(phys_base)=-1845493760\nKERNELOFFSET=1b000000\n";
        let info = VmcoreInfo::parse(&note(x86)).unwrap();
        assert_eq!(info.architecture(), VmcoreArchitecture::X86_64);
        assert_eq!(info.arm64_kernel_root(), None);

        let neither = "OSRELEASE=6.1.0\nPAGESIZE=4096\n";
        let info = VmcoreInfo::parse(&note(neither)).unwrap();
        assert_eq!(info.architecture(), VmcoreArchitecture::Unknown);
    }

    #[test]
    fn the_kernels_own_format_strings_are_not_a_note() {
        // What the sweep meets first in the real dump: .rodata's
        // "OSRELEASE=%s\n\0\0\0PAGESIZE=%ld\n".
        let rodata = b"OSRELEASE=%s\n\0\0\0PAGESIZE=%ld\n\0\0\0init_uts_ns\0";
        assert!(matches!(
            VmcoreInfo::parse(rodata),
            Err(VmcoreInfoError::NotVmcoreinfo(_))
        ));
        assert!(matches!(
            VmcoreInfo::parse(b"PAGESIZE=4096\n\0"),
            Err(VmcoreInfoError::NotVmcoreinfo(_))
        ));
    }

    #[test]
    fn a_truncated_note_is_refused_not_read_as_far_as_it_goes() {
        // Cut mid-line: the last line has no newline before the NUL.
        let cut = "OSRELEASE=4.19.0-11-arm64\nPAGESIZE=4096\nSYMBOL(swapper_pg_dir)=ffff00";
        assert!(matches!(
            VmcoreInfo::parse(&note(cut)),
            Err(VmcoreInfoError::Truncated(_))
        ));
        // No NUL at all inside the window.
        let mut long = DEBIAN_ARM64.as_bytes().to_vec();
        while long.len() < MAX_VMCOREINFO_BYTES + 10 {
            long.extend_from_slice(b"OFFSET(x.y)=1\n");
        }
        assert!(matches!(
            VmcoreInfo::parse(&long),
            Err(VmcoreInfoError::Truncated(_))
        ));
    }

    #[test]
    fn a_note_that_disagrees_with_itself_is_refused() {
        let text = format!("{DEBIAN_ARM64}SYMBOL(swapper_pg_dir)=ffff0000092ef000\n");
        match VmcoreInfo::parse(&note(&text)) {
            Err(VmcoreInfoError::Conflicting { key, .. }) => {
                assert_eq!(key, "SYMBOL(swapper_pg_dir)")
            }
            other => panic!("expected a conflict, got {other:?}"),
        }
        // Repeating a line with the same value is not a disagreement.
        let text = format!("{DEBIAN_ARM64}PAGESIZE=4096\n");
        assert!(VmcoreInfo::parse(&note(&text)).is_ok());
    }

    #[test]
    fn a_value_not_in_its_keys_form_is_malformed() {
        for bad in [
            "OSRELEASE=4.19\nSYMBOL(x)=0xffff000008000000\n",
            "OSRELEASE=4.19\nSYMBOL(x)=zz\n",
            "OSRELEASE=4.19\nPAGESIZE=4k\n",
            "OSRELEASE=4.19\nNUMBER(VA_BITS)=forty\n",
            "OSRELEASE=4.19\nno equals sign here\n",
        ] {
            assert!(
                matches!(
                    VmcoreInfo::parse(&note(bad)),
                    Err(VmcoreInfoError::Malformed { .. })
                ),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn copies_that_disagree_are_not_reconciled_by_choosing_one() {
        let a = VmcoreInfo::parse(&note(DEBIAN_ARM64)).unwrap();
        let b = VmcoreInfo::parse(&note("OSRELEASE=4.19.0-10-arm64\nPAGESIZE=4096\n")).unwrap();
        let same = VmcoreSweep {
            found: vec![(0x1000, a.clone()), (0x9000, a.clone())],
            complete: true,
            ..VmcoreSweep::default()
        };
        assert_eq!(same.agreed().unwrap(), Some(&a));
        let split = VmcoreSweep {
            found: vec![(0x1000, a), (0x9000, b)],
            complete: true,
            ..VmcoreSweep::default()
        };
        assert!(matches!(
            split.agreed(),
            Err(VmcoreInfoError::Conflicting { .. })
        ));
        let clean = VmcoreSweep {
            complete: true,
            ..VmcoreSweep::default()
        };
        assert_eq!(clean.agreed().unwrap(), None);
    }

    #[test]
    fn a_sweep_cut_short_is_could_not_look_not_no_copy() {
        // Nothing found by a sweep that stopped early is not "no copy".
        assert_eq!(
            VmcoreSweep::default().agreed(),
            Err(VmcoreInfoError::SweepIncomplete { found: 0 })
        );
        // Nor are copies found by one: an unseen copy may contradict them.
        let a = VmcoreInfo::parse(&note(DEBIAN_ARM64)).unwrap();
        let partial = VmcoreSweep {
            found: vec![(0x1000, a)],
            ..VmcoreSweep::default()
        };
        assert_eq!(
            partial.agreed(),
            Err(VmcoreInfoError::SweepIncomplete { found: 1 })
        );
    }

    // ---------------------------------------------------------------------
    // The root proof on synthetic tables. Written from ARM DDI 0487 D8.3
    // (4 KiB granule): these pin the mechanism — one regime proves, the
    // others are named and fail — and are not validation on real evidence,
    // which is `tests/arm64_vmcoreinfo_real_test.rs`.
    // ---------------------------------------------------------------------

    use seance_core::data_source::ByteSliceDataSource;

    const RELEASE: &str = "6.0.0-synthetic";
    /// `init_uts_ns` sits at physical 0x20_0040.
    const UTS_PHYS: u64 = 0x20_0040;

    /// A 4 MiB image whose tables follow `chain` (one `(table, index)` per
    /// level, top down) to the page at 0x20_0000, which holds a
    /// `uts_namespace` naming `RELEASE`.
    fn image(chain: &[(u64, u64)]) -> Arc<dyn MemoryLayer> {
        let mut bytes = vec![0u8; 0x40_0000];
        for (position, (table, index)) in chain.iter().enumerate() {
            let target = chain.get(position + 1).map_or(0x20_0000, |next| next.0);
            // Valid + table/page (bits 1:0 = 0b11), AF (bit 10) on the page.
            let value = target
                | 0b11
                | if position + 1 == chain.len() {
                    1 << 10
                } else {
                    0
                };
            let at = (table + index * 8) as usize;
            bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
        }
        let uts = UTS_PHYS as usize;
        bytes[uts + 4..uts + 9].copy_from_slice(b"Linux");
        let release = uts + 4 + 65 + 65;
        bytes[release..release + RELEASE.len()].copy_from_slice(RELEASE.as_bytes());
        Arc::new(
            seance_memory::PhysicalLayer::raw(Arc::new(ByteSliceDataSource::new(bytes)))
                .expect("a non-empty image"),
        )
    }

    fn synthetic_note(voffset: u64, va_bits: u64) -> VmcoreInfo {
        let text = format!(
            "OSRELEASE={RELEASE}\nPAGESIZE=4096\nSYMBOL(init_uts_ns)={:x}\n\
             SYMBOL(swapper_pg_dir)={:x}\nNUMBER(VA_BITS)={va_bits}\n\
             NUMBER(kimage_voffset)={voffset:#x}\n",
            voffset + UTS_PHYS,
            voffset + 0x10_0000,
        );
        VmcoreInfo::parse(&note(&text)).expect("a well-formed note")
    }

    /// Kernel image at VA `0xffff_0000_0800_0000` over PA 0: `init_uts_ns` at
    /// VA `0xffff_0000_0820_0040` takes L0 0, L1 0, L2 0x41, L3 0.
    const VOFFSET_48: u64 = 0xffff_0000_0800_0000;
    const CHAIN_48: [(u64, u64); 4] = [
        (0x10_0000, 0),
        (0x10_1000, 0),
        (0x10_2000, 0x41),
        (0x10_3000, 0),
    ];
    /// Kernel image at VA `0xffff_ff80_0800_0000`: the same address bits
    /// below 39 take L1 0, L2 0x41, L3 0.
    const VOFFSET_39: u64 = 0xffff_ff80_0800_0000;
    const CHAIN_39: [(u64, u64); 3] = [(0x10_0000, 0), (0x10_1000, 0x41), (0x10_2000, 0)];

    #[test]
    fn the_root_proves_under_the_one_regime_that_reads_the_release_back() {
        let proof =
            prove_arm64_kernel_root(&image(&CHAIN_48), &synthetic_note(VOFFSET_48, 48)).unwrap();
        assert_eq!(proof.root, 0x10_0000);
        assert_eq!(
            (proof.regime.granule(), proof.regime.va_bits()),
            (Arm64Granule::Kb4, 48)
        );
        assert_eq!(proof.tried.len(), ARM64_KERNEL_REGIMES.len());

        let proof =
            prove_arm64_kernel_root(&image(&CHAIN_39), &synthetic_note(VOFFSET_39, 39)).unwrap();
        assert_eq!(
            (proof.regime.granule(), proof.regime.va_bits()),
            (Arm64Granule::Kb4, 39)
        );
    }

    #[test]
    fn a_regime_the_note_contradicts_is_not_chosen() {
        // The tables are 48-bit; the note says VA_BITS 39.
        let err = prove_arm64_kernel_root(&image(&CHAIN_48), &synthetic_note(VOFFSET_48, 39))
            .err()
            .expect("a contradiction");
        assert!(
            matches!(err, Arm64RootRefusal::DisagreesWithNote { .. }),
            "{err}"
        );
    }

    #[test]
    fn tables_that_prove_nothing_name_every_regime_tried() {
        let err = prove_arm64_kernel_root(&image(&[]), &synthetic_note(VOFFSET_48, 48))
            .err()
            .expect("no tables");
        let text = err.to_string();
        assert!(matches!(err, Arm64RootRefusal::NoRegimeProves { .. }));
        for needle in [
            "arm64_4k_ttbr1 (48-bit VA)",
            "arm64_64k_ttbr1 (42-bit VA)",
            RELEASE,
        ] {
            assert!(text.contains(needle), "{text}");
        }
    }

    #[test]
    fn a_note_from_another_architecture_anchors_no_arm64_proof() {
        let x86 = VmcoreInfo::parse(&note(
            "OSRELEASE=5.15.0\nSYMBOL(init_top_pgt)=ffffffff9ce10000\n",
        ))
        .unwrap();
        assert!(matches!(
            prove_arm64_kernel_root(&image(&CHAIN_48), &x86),
            Err(Arm64RootRefusal::NoteInsufficient(_))
        ));
    }
}
