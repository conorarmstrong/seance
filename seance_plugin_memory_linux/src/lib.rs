#![forbid(unsafe_code)]
//! # Séance Linux memory analysis
//!
//! The Linux member of the memory-analysis tier. It takes the decoded physical
//! address space the container stage ([`seance_memory::MemoryImageModule`])
//! attached to a `MemoryImage` record, establishes which kernel the capture was
//! taken from, and reads kernel structures out of it.
//!
//! ## The one idea this crate is built around
//!
//! > **A structure member that is absent because this kernel build never had it
//! > is `not_declared`. It is not incompleteness, and it is not an error.**
//!
//! Volatility 3's Linux support carries 231 `has_member` branches. That count is
//! the measure of how much varies between kernels, and it is why nothing here
//! reads a member by a single hardcoded name. Every stage declares what it wants
//! as a [`seance_memory::binding::MemberSet`] — ordered candidates for the
//! **type** name and ordered candidates for the **member path**, because both
//! dimensions vary in real evidence — and
//! [`seance_memory::binding::MemberSet::bind`] resolves it, yielding
//! [`seance_memory::binding::Field::NotDeclared`] by default rather than an
//! error. A stage fails only for something it declared
//! [`seance_memory::binding::Necessity::Required`], and every such declaration
//! carries a written statement of what the stage cannot do without it, printed
//! verbatim to the examiner.
//!
//! This is not theoretical. Volatility's own `linux.capabilities` **fails** on
//! the Debian 3.2 sample this crate was written against, producing one row and
//! an error reading *"Volatility encountered an unexpected situation. No further
//! results will be produced."* The cause is that Debian 3.2 names the type
//! `kernel_cap_t` where the extension is registered on `kernel_cap_struct`, and
//! `cap_ambient` (Linux 4.3 and later) does not exist on it. Byte for byte it is
//! the same defect that cost the Windows tier eight analysis stages on a real
//! Windows XP capture.
//!
//! ## The chain everything rests on
//!
//! Linux publishes nothing about itself the way a Windows crash dump does — no
//! header naming the directory table base, no `KdDebuggerDataBlock`. What it has
//! is the kernel banner, and [`discovery`] turns that one string into a proved
//! page-table root:
//!
//! ```text
//!   sweep physical memory for "Linux version "   -> the banner, and where it is
//!   match it against an ISF's linux_banner       -> the symbol table
//!   ISF banner address - physical address        -> the kernel text shift
//!   page-table symbol address - shift            -> the directory table base
//!   translate the banner back to where it was    -> the root is proved, not guessed
//! ```
//!
//! The last line is the one that matters. A shift taken as the linker's constant
//! is wrong on any relocated or KASLR'd kernel, and a wrong root does not fail —
//! it walks bytes that are not a page table and yields addresses that are
//! plausible and false. Nothing in this crate reads a structure until that walk
//! has been checked against a value the image itself supplied.
//!
//! ## What this tier actually runs
//!
//! Twelve stages, listed in [`module::STAGES`] and published with every
//! analysis as a stage manifest so the case records what this build could have
//! run:
//!
//! | Stage | Module | What an examiner gets |
//! |---|---|---|
//! | [`module::STAGE_LINUX_PROCESSES`] | [`tasks`] | Every process on the kernel's task list, walked from `init_task`, corroborated against an independent physical sweep. |
//! | [`module::STAGE_LINUX_CAPABILITIES`] | [`capabilities`] | Each process's capability sets (effective, permitted, inheritable, bounding, ambient), decoded to named capabilities. |
//! | [`module::STAGE_LINUX_KERNEL_MODULES`] | [`lsmod`] | Every loaded kernel module, walked from the `modules` list head, corroborated against an independent physical sweep. |
//! | [`module::STAGE_LINUX_KERNEL_LOG`] | [`kernel_log`] | The kernel log ring (`dmesg`) still resident in memory — each line's priority, facility, timestamp and message. |
//! | [`module::STAGE_LINUX_KERNEL_HOOKS`] | [`hooks`] | The system-call tables, every `ftrace` registration and direct call, every kprobe and every loaded eBPF program, each attributed to the kernel's text, a named module, or nothing known — with what could not be checked named. |
//! | [`module::STAGE_LINUX_PROCESS_MAPS`] | [`proc_maps`] | Each process's virtual memory areas — range, permissions, backing file with its mount-crossing path — walked from `mm_struct.mmap` or the 6.1+ maple tree. |
//! | [`module::STAGE_LINUX_OPEN_FILES`] | [`lsof`] | Each process's open file descriptors — number, mount-crossing path or `socket:[inode]` / `pipe:[inode]` / `anon_inode:<name>`, mode and flags — walked from its file-descriptor table. |
//! | [`module::STAGE_LINUX_NETWORK_SOCKETS`] | [`sockstat`] | Each process's network sockets — family, type, protocol, state, and for IPv4 the source/destination address and port. |
//! | [`module::STAGE_LINUX_MOUNTS`] | [`mounts`] | Filesystems mounted per namespace — device, absolute mount point, filesystem root and decoded flags. |
//! | [`module::STAGE_LINUX_COMMAND_LINES`] | [`cmdline`] | Each process's argument vector, read from the bracket `mm_struct.arg_start`/`arg_end` names in that process's own memory. |
//! | [`module::STAGE_LINUX_BASH_HISTORY`] | [`bash`] | Commands typed into a shell, recovered from the shell's own heap. |
//! | [`module::STAGE_LINUX_ENVIRONMENT`] | [`envars`] | Each process's environment, read from that process's own user memory. |
//!
//! Supporting them: [`profile`] (what discovery established, and how strongly),
//! [`space`] (opening one process's address space through its `mm_struct.pgd`),
//! [`paths`] (the kernel's `prepend_path` over the dentry and mount chains, and
//! the pseudo-file names), [`read`] (typed member reads that keep "this build
//! has no such member" apart from "these bytes were not acquired"), and
//! [`error`] (why a stage could not run at all).
//!
//! ## What this tier does **not** do yet
//!
//! Stated plainly, because an absent stage and a stage that found nothing are
//! opposite findings and this list is the only thing that separates them:
//!
//! * **x86-64, and arm64 at 4, 16 and 64 KiB pages, the last two on QEMU evidence.** Both
//!   x86-64 paging depths are read — four-level and five-level (LA57) — and
//!   which one a capture used is *proved* rather than assumed: `CR4.LA57`
//!   appears in no capture, so the page tables are walked at each depth
//!   [`discovery::PAGING_MODES`] offers and the depth that translates the
//!   kernel banner back to where the sweep found it is the one used. The same
//!   proof is offered the arm64 kernel regimes, the family chosen by symbols
//!   only one architecture defines. Real arm64 kernels have been profiled: a
//!   Debian 4.19 guest (4 KiB), a Debian 6.12 kernel (16 KiB) and an Ubuntu
//!   6.8 kernel (64 KiB), the last two booted under QEMU TCG — emulated, not
//!   hardware (`VALIDATION.md` `MEM-ARM-4`, `MEM-ARM-5`, `MEM-ARM-6`); the
//!   file offsets in `proc_maps` take the page size from the proved regime.
//!   A 32-bit kernel and an arm64 kernel whose tables prove under no regime
//!   offered (LPA2 and `DS = 1` among them) are refused by name in
//!   [`discovery::DiscoveryError::UnsupportedArchitecture`], not analysed
//!   badly; an x86-64 capture whose depth cannot be demonstrated ends at
//!   [`discovery::DiscoveryError::PageTablesUnproved`], which names the depths
//!   it tried. [`vmcoreinfo`] reads the kernel's own `VMCOREINFO` and proves
//!   the arm64 root it names.
//! * **Linux 6.4's `module.mem[]` is decoded through `mod_mem_type`.** When
//!   the symbol table declares that enumeration — an image-derived table does,
//!   from the kernel's BTF — the module stage publishes every region by name
//!   and fills the size columns from them, and the hook stage attributes
//!   addresses to its `MOD_TEXT` region. When it does not, the module list is
//!   produced with its size columns absent and a sentence on the row saying
//!   why — never blank — and the hook stage reads `mem[0]` itself, stating the
//!   `MOD_TEXT` index it assumed.
//! * **Paths cross mount points where the build allows it, and each record
//!   says which walk it got.** A record whose `f_path.mnt`, mount chain or
//!   `task->fs` would not read falls back to the reduced in-mount walk and
//!   carries `path_scope: dentry_tree_relative` with the reason
//!   ([`paths::PathScope`]); a survey-level flag is never the whole story.
//!   Pseudo-files are decoded for `sockfs_dname`, `pipefs_dname` and
//!   `anon_inodefs_dname` and carry `path_scope: pseudo` — no walk is made for
//!   them and none is described; any other `d_dname` (namespace files, for
//!   one) is named on the record with the raw dentry walk beside it.
//! * **The 5.10+ printk_ringbuffer log is not decoded.** The flat pre-3.5 ring
//!   and the 3.5–5.10 structured record ring are read (the structured path
//!   validated only against synthetic fixtures until a 3.5–5.10 capture is in the
//!   corpus); the 5.10+ ring buffer is refused by name rather than shown empty.
//! * **A command line is the bracket, and only the bracket.** A process that
//!   rewrote its argument area (`setproctitle`) is flagged `argv_rewritten`
//!   only when the whole bracket was read; a bracket the acquisition cut short
//!   is `argv_short_read` with the bytes missing counted, and a missing page
//!   is never reported as a rewrite. The kernel's `/proc/<pid>/cmdline` would
//!   read on into the environment area, and this stage does not.
//! * **Hook detection stops at registrations.** The hook stage reads what the
//!   kernel registered — table entries, `ftrace_ops`, direct calls, kprobes,
//!   eBPF programs — and attributes each. It does not compare kernel text
//!   against a pristine copy, does not walk perf events to tie a `KPROBE`
//!   program to its probe, does not walk the `dyn_ftrace` patch records, and
//!   does not decode BPF trampolines to name which program a direct call
//!   reaches; a direct call no listed program explains is reported as such.
//!   The eBPF registry is walked only in its 4.20+ xarray shape; the radix
//!   tree and the layered IDR before it are refused by name.
//! * **No scan-based recovery.** Everything here follows live kernel links, so a
//!   structure the kernel no longer points at is not found.
//! * **Swap is identified, and read when the area is attached.** The physical
//!   capture does not hold a page that was paged out at acquisition, but the
//!   address space tells a page whose contents the kernel moved out apart from
//!   an address that was never mapped (`PteSemantics::Linux` /
//!   `TranslateError::LinuxSwapEntry`), and — given the swap area — reads it.
//!   Attach a capture's swap areas with `SEANCE_SWAPFILES` as `index=path` (the
//!   Linux counterpart of the Windows tier's `SEANCE_PAGEFILES`; the index is
//!   the area's `swp_type`), and a swapped page resolves to its bytes on any
//!   read through a process's address space. The x86-64 swap-entry layout
//!   changed once (the L1TF inversion, backported below 4.19) and a single entry
//!   does not say which wrote it, so both are decoded and the page is read only
//!   through the attached area whose bounds one layout's offset lands inside —
//!   an uncorroborated or ambiguous entry stays a hole rather than being read
//!   from the wrong place. With no area attached, or for a page no area
//!   corroborates, the page is a gap counted against the stage's completeness,
//!   never an absence. Every profile record carries a `swap` block saying which
//!   ([`profile::SWAP_RESOLVED`] / [`profile::SWAP_NOT_RESOLVED`]).
//! * **No wall-clock process start times.** Linux stores an offset from boot, and
//!   converting it needs the boot wall-clock time, which this tier does not yet
//!   establish. The raw value is published with its unit, and never as a date.
//! * **Symbols must already be in the lab.** No ISF is fetched or generated; a
//!   kernel with no matching symbol file is reported as such, with the banner
//!   quoted so one can be obtained.
//!
//! ## Reaching the orchestrator
//!
//! [`module::linux_memory_module`] wraps [`module::LinuxMemoryAnalysis`] in the
//! shared [`seance_memory::analysis::MemoryAnalysisModule`], which is the
//! `ForensicsModule` the orchestrator registers. That wrapper — rather than a
//! `ForensicsModule` written here — is deliberate: the subscription filter, the
//! "is this actually a memory image" check and the layer reconstruction are
//! written once in [`seance_memory::analysis`], so this tier cannot be wired up
//! wrongly. `seance_cli::main` registers it beside the Windows tier; both run on
//! the same `MemoryImage` record and each returns nothing for an image that is
//! not its operating system.

pub mod bash;
pub mod capabilities;
pub mod cmdline;
pub mod discovery;
pub mod envars;
pub mod error;
pub mod fdtable;
pub mod hooks;
pub mod image_symbols;
pub mod kernel_log;
pub mod lsmod;
pub mod lsof;
pub mod modscan;
pub mod module;
pub mod mounts;
pub mod paths;
pub mod proc_maps;
pub mod profile;
pub mod read;
pub mod sockstat;
pub mod space;
pub mod swap;
pub mod tasks;
pub mod taskscan;
pub mod vmcoreinfo;

pub use discovery::{
    discover, discover_reported, DiscoveryError, DiscoveryOptions, DiscoveryReport,
};
pub use error::StageError;
pub use module::{
    linux_memory_module, LinuxMemoryAnalysis, MODULE_ID, MODULE_VERSION, STAGES,
    STAGE_LINUX_BASH_HISTORY, STAGE_LINUX_ENVIRONMENT, STAGE_LINUX_KERNEL_MODULES,
    STAGE_LINUX_PROCESSES,
};
pub use profile::{Evidence, Found, KernelShift, LinuxBuild, LinuxProfile};

#[cfg(test)]
mod tests {
    /// Every source file in `src/` must be declared above.
    ///
    /// This is the failure that broke the workspace, written down. `tasks.rs`,
    /// `lsmod.rs`, `envars.rs` and `bash.rs` were all finished, and none of them
    /// was reachable, because there was no crate root declaring them. An
    /// undeclared file is not dead code a linter will mention — it is not
    /// compiled at all, so nothing in it runs, no stage in it dispatches, and no
    /// test in it can fail. The crate had 3,750 lines of real analysis and a
    /// manifest `cargo` could not even parse.
    ///
    /// Reading the directory rather than keeping a second list is the point: a
    /// list would be one more thing to forget to update, which is the same
    /// defect one level up.
    #[test]
    fn every_source_file_in_this_crate_is_declared_as_a_module() {
        let declared: Vec<&str> = include_str!("lib.rs")
            .lines()
            .filter_map(|line| line.trim().strip_prefix("pub mod "))
            .filter_map(|rest| rest.strip_suffix(';'))
            .collect();
        assert!(
            declared.len() > 1,
            "the module list could not be read out of lib.rs, so this guard is not guarding"
        );

        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let entries =
            std::fs::read_dir(&dir).expect("the crate's own source directory is readable");
        let mut checked = 0usize;
        for entry in entries {
            let path = entry.expect("a readable directory entry").path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let stem = path
                .file_stem()
                .and_then(|s| s.to_str())
                .expect("a source file has a name")
                .to_string();
            if stem == "lib" {
                continue;
            }
            checked += 1;
            assert!(
                declared.contains(&stem.as_str()),
                "src/{stem}.rs exists and lib.rs does not declare it, so none of it is compiled, \
                 no test in it runs, and no analysis stage in it can ever dispatch"
            );
        }
        assert_eq!(
            checked,
            declared.len(),
            "lib.rs declares a module with no source file behind it, or the scan missed one: \
             declared {declared:?}"
        );
    }
}
