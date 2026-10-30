# Build-variant member resolution

**Status:** implemented and in use. The binding lives in
`seance_memory/src/binding/` and is re-exported from `seance_memory/src/lib.rs`. Three
memory tiers consume it: `seance_plugin_memory_windows`, `seance_plugin_memory_linux`
and `seance_plugin_memory_macos`.

The Linux tier this was built as a prerequisite for exists, is registered in
`seance_api/src/modules.rs`, runs **twelve** stages, and matches Volatility 3 on a real
Debian capture for the task list, capabilities, kernel modules, shell history and
environment — asserted by `seance_plugin_memory_linux/tests/parity_linux.rs`.

**That assertion has never run in CI**, because the reference image is not committed
and the test skips when `SEANCE_MEM_IMAGES` is unset. The gate lives in `seance_core::test_support::corpus` and separates the
two cases — an unprovisioned corpus skips and says so, a corpus that is *named* and
missing fails — and `SEANCE_REQUIRE_CORPUS=1` turns the skip itself into a failure, so
CI can demand the comparison actually happened. Setting that variable in CI still
requires somewhere to put the image.

This document describes what is there. What remains open is in
[What is still outstanding](#what-is-still-outstanding), and nothing else here should be
read as future work.

## The defect this removes

A real Windows XP capture produced **3 of 20 stages complete, 9 failed**.
Eight of the nine failures were one line:

```rust
// poolscan.rs:807
reader.member_offset(TYPE_OBJECT_HEADER, "InfoMask")?;   // statement position
```

The offset is discarded — the call is a pure existence proof. `InfoMask` arrived in
Vista; XP and 2003 carry `NameInfoOffset` / `HandleInfoOffset` / `QuotaInfoOffset` as
direct bytes. The `?` turns `SymbolError::UnknownMember` into a `PoolError` variant
declared `#[error(transparent)]`, so it surfaces to the examiner verbatim, with no
sentence explaining what it means.

**The member is never read on XP.** It is consumed only under `if symbols.top_down`,
which is Windows 8 and later. XP takes the bottom-up path, which never touches it. So
a member no XP code path reads killed pool scanning, cross-view, services, kernel
objects, VAD, syscall scanning, tampering and recovered-files — including VAD, which
uses `PoolSymbols` for exactly one `_POOL_HEADER` fact and never reads an object
header at all.

**The class:** *a build-variant member proved fatally in a pre-flight that the branch
reading it never reaches.*

## Why it was built once, in `seance_memory`, rather than in one tier

Four things were private to the Windows tier: `Field<T>`, `first_member`, `StageId` and
the stage manifest, and `Evidence`/`Found`. Three independent measurements said the same
thing, and all three are why those four were lifted into `seance_memory` rather than
fixed in place.

**Linux is this problem 231 times over.** That is the count of `has_member` branches
across `reference/volatility3/volatility3/framework/{symbols,plugins}/linux/`. Writing
the Linux tier the way the Windows tier was written would have reproduced the
nine-stages-dead outcome on the first non-canonical kernel.

**Volatility itself fails this way on our sample.** The oracle records
`linux.capabilities` as a failure — one row, and an `.err` reading *"Volatility
encountered an unexpected situation. No further results will be produced."* Debian 3.2
names the type `kernel_cap_t` where the extension is registered on `kernel_cap_struct`,
and `cap_ambient` (Linux 4.3+) does not exist. Byte for byte, it is `InfoMask`.

**macOS is the same shape again**, across 129 real Kernel Debug Kit packs spanning
10.6.4 to 10.15.4: `trap_table` absent in 24 packs, `BootPML4` / `vm_kernel_stext` /
`vm_kernel_etext` absent in 12, `ifnet_head` absent in 6 (fallback `dlil_ifnet_head`),
type `kevent_qos_s` absent in 34. Credentials need a fallback in **both** directions —
`ucred.cr_posix` is absent in 6 packs where `ucred.cr_uid` exists, and `ucred.cr_uid`
is absent in the other 123.

The last one is why candidate lists are ordered in **two** dimensions: candidate type
names as well as candidate member paths.

## The rule

> A structure member that is absent because this kernel build never had it is
> **`not_declared`**. It is not incompleteness, and it is not an error.

Those claims are different and an examiner acts on each differently:

| Outcome | What it means | What the examiner does |
|---|---|---|
| `Field::Known(v)` | the value was read | reads it |
| `Field::NotApplicable` | the member exists and this row has no value for it | nothing was missed |
| `Field::NotDeclared` | this build has no such member | nothing was missed; the column does not exist here |
| `Field::Unavailable` | the member exists, the bytes would not read | the evidence is damaged here |
| `BindError` | the analysis could not run at all | re-run, or the tool cannot do this |

Escalating `NotDeclared` into `BindError` — the pre-binding behaviour — tells an
examiner the analysis could not run, when in truth it ran fine and one column does not
exist on this operating system. Escalating it to *incompleteness* would be just as wrong
in the other direction: it would say evidence was missed when none was.

`NotDeclared` also covers a member whose **containing type** the build does not declare.
The Windows session id is read through `_EPROCESS.Session` → `_MM_SESSION_SPACE.SessionId`;
on Windows 11 24H2+ the pointer's target is a `_PSP_SESSION_SPACE` no ISF declares, so
the field is `NotDeclared { member: "_MM_SESSION_SPACE.SessionId" }` — the pointer read,
nothing was missed, and no number is read at an assumed offset. The Windows process list
discloses such columns once, with a count, under `undescribed`, and they do not make the
process inventory a floor.

## The model as implemented

`seance_memory/src/binding/`, four files plus tests:

| File | What is in it |
|---|---|
| `field.rs` | `Field<T>` — one fact, with the four outcomes kept apart, and its wire shape |
| `members.rs` | `MemberSet` / `MemberSpec` / `TypeSpec` / `Necessity`, resolution, `BuildBinding`, `BindError`, `first_member`, `first_type` |
| `stage.rs` | `StageId`, `MEMORY_STAGE_MANIFEST_RECORD` |
| `evidence.rs` | `Evidence` / `Found` — how a discovered fact was established |
| `tests.rs` | the binding's own tests, against a deliberately XP-shaped fixture (`rg -c '#\[test\]' seance_memory/src/binding/tests.rs`) |

`seance_memory/src/lib.rs` re-exports `first_member`, `first_type`, `BindError`,
`BoundMember`, `BoundType`, `BuildBinding`, `Evidence`, `Field`, `Found`, `MemberSet`,
`MemberSpec`, `MemberUse`, `Necessity`, `StageId`, `TypeSpec`, `TypeUse` and
`MEMORY_STAGE_MANIFEST_RECORD`.

### `Field<T>` — the four outcomes

```rust
pub enum Field<T> {
    Known(T),
    NotApplicable,
    NotDeclared { member: &'static str },
    Unavailable(String),
}
```

`NotDeclared` carries the member name so a report can say what was looked for; when
several spellings were accepted it is the first candidate, the canonical name for the
thing that is missing.

`to_json_with` emits `{"kind": …}` with kind-specific siblings `value`, `member` and
`detail`. `Field<u64>::to_json_address` adds a `value_hex` sibling beside `value`,
because a kernel pointer above 2^53 arrives at a JSON consumer rounded.

The wire shape is fixed by its consumer. `frontend/src/pages/memory/normalize.ts`
switches on `kind` and prints a different sentence for each — for `not_declared`, *"The
kernel build running on this machine has no such structure member, so there was never a
value to read."* — and falls through to `malformed` for anything it does not recognise.
A renamed kind blanks a column rather than failing a build, which is why
`field.rs::every_kind_has_the_wire_name_the_frontend_decodes` asserts the four strings
literally.

### Declaration: `MemberSet`, `MemberSpec`, `TypeSpec`, `Necessity`

A stage declares; `MemberSet::bind(&StructReader)` resolves. Nothing between the two can
turn an absent build-variant member into a stage failure.

```rust
pub struct MemberSet {
    pub stage: StageId,
    pub types: &'static [TypeSpec],
    pub members: &'static [MemberSpec],
}

pub struct MemberSpec {
    pub key: &'static str,                     // how the stage refers to it
    pub types: &'static [&'static str],        // candidate type names, preferred first
    pub members: &'static [&'static str],      // candidate member paths, preferred first
    pub necessity: Necessity,
}

pub enum Necessity {
    Optional,                                  // the default
    Required { without_it: &'static str },
}
```

All the constructors are `const`, so a tier declares its layout as a `const` item and no
resolution happens until `bind` runs. A member path may reach through embedded
aggregates with `.` — `"cr_posix.cr_uid"`, `"start_time.tv_sec"`, `"core_layout.base"` —
and never dereferences a pointer.

`Necessity::Optional` is the default, and the rustdoc says why: *"the alternative is what
killed eight stages on a Windows XP image."* `Required` is the only route to a stage
failure, and `without_it` is printed verbatim to the examiner. The rustdoc rejects
"Needed for parsing" as a non-justification by name.

`bind` reads no memory. It is a pure symbol-table question, so it runs once at the top of
a stage and the answer is carried through the walk.

### Resolution outcomes

```rust
pub enum MemberUse {
    Declared { type_name: &'static str, member: &'static str, offset: u64 },
    NotDeclared,
    Unavailable { detail: String },
}
```

`TypeUse` is the same three shapes with `type_name` and `size`. Resolution walks the type
candidates in order and, within each, the member candidates in order, taking the first
pair this build declares. A genuine table failure seen along the way is remembered and
reported only if no candidate resolved, so a build that declares a later candidate is
still answered rather than blamed for an earlier one.

**Absence is classified rather than lumped.** `members.rs::is_absence` treats exactly
three symbol errors as "this build's layout does not provide it":

- `UnknownType` — no type of that name in this build.
- `UnknownMember` — the type exists and has no such field.
- `WrongTypeKind` — the name exists but is not an aggregate. This is what `kernel_cap_t`
  looks like on a kernel where it is a typedef to a scalar.

Everything else — a shadowed name the table refuses to disambiguate, an unresolved type
reference, an overflowed offset, a path deeper than the reader walks — means the question
was put and could not be answered, and lands as `Unavailable`. Calling that "this build
has no such member" would be a fabricated claim about the suspect's machine. The
unresolved reference is kept out of `WrongTypeKind` deliberately: a reference the ISF
never defined fails at the point of use as `SymbolError::UnresolvedType`, and folding the
two together would report "this kernel has no such member" over a table the analysis
simply failed to load.

### The binding

`BuildBinding` holds the resolved `BoundType`s and `BoundMember`s in declaration order.
`member(key)` and `type_of(key)` look one up; an unknown key is `BindError::UndeclaredKey`
rather than "not declared", because those are opposite claims — the first says the
analysis asked the wrong question, the second says the machine had no answer.

`read_unsigned` and `read_pointer` produce the ergonomic path: a member this build does
not declare returns `Field::NotDeclared`, a member whose bytes were not acquired returns
`Field::Unavailable`, and neither stops the stage. Reading a member from an object of the
wrong type is `BindError::WrongObjectType` rather than a read, because the offset is real
and the bytes at it in an unrelated structure parse into a plausible wrong answer nothing
downstream could catch.

`BuildBinding::to_json` is the layout record: for every member the stage wanted, whether
this build had it, which of the accepted names it had it under, and where. That is what
makes a blank column readable, and what a defence expert needs to check the analysis
against the same symbol pack.

### `BindError` — every variant is a genuine stop

`RequiredNotDeclared`, `RequiredUnresolved`, `UndeclaredKey`, `DuplicateKey`,
`NoCandidates`, `WrongObjectType`. Each carries a `class()` string for artifact metadata
and a `stage()`. A build-variant member this kernel does not have is deliberately absent
from the enum.

The two hygiene variants are worth naming: a key declared twice makes a later lookup
ambiguous, and a spec with no candidate names leaves nothing to look for and nothing to
name in a report that says it is absent. Both are refused at `bind` time.

### The low-level idiom

`first_member(reader, type_name, candidates)` and `first_type(reader, candidates)` remain,
for the cases a declaration does not fit. Both return
`Result<Option<&str>, _>` — three outcomes, not two:

- `Ok(Some(name))` — this build declares it, under this name.
- `Ok(None)` — this build declares none of them. Nothing was missed.
- `Err` — the symbol table could not answer, for a reason that is not absence.

The prior version returned a bare `Option` and used `member_offset(..).is_ok()`, which
collapsed the third outcome into the second.

### `StageId` and `Evidence`

`StageId` binds three facts that used to be written out separately at every emit site: the
stage key, the record type, and whether the stage emits one record per process. When they
drifted the analysis ran, wrote its records, and the API served `did_not_run` over them.
`MEMORY_STAGE_MANIFEST_RECORD` is the record type an analysis publishes listing every
stage that build could have run; `seance_api::memory::declared_stages` reads it by the
field names `StageId::to_json` writes.

`Evidence` grades how a fact was established — `Confirmed`, `Validated`, `Scanned`,
`Supplied` — and `Ord` follows strongest-to-weakest, so `max()` over a chain is its
weakest link. `Found<T>` pairs a value with its grade so the provenance survives being
passed somewhere.

## How a stage declares what it binds

### The direct fix of the original defect

`seance_plugin_memory_windows/src/poolscan.rs` now carries **two** declarations, and the
split is the fix. `POOL_LAYOUT` is what every build binds:

```rust
const POOL_LAYOUT: MemberSet = MemberSet::new(
    STAGE_POOL_SCAN,
    &[
        TypeSpec::new("pool_header", &[TYPE_POOL_HEADER]).required(
            "a pool allocation cannot be sized or located, so no candidate object can be found \
             at all",
        ),
        TypeSpec::new("object_header", &[TYPE_OBJECT_HEADER]),
    ],
    &[
        MemberSpec::new("pool_tag", &[TYPE_POOL_HEADER], &["PoolTag"]).required(
            "the four bytes a scan matched cannot be placed inside the allocation they belong \
             to, so no allocation base can be computed and no object follows from a tag",
        ),
        MemberSpec::new("block_size", &[TYPE_POOL_HEADER], &["BlockSize"]).required(
            "an allocation's length is unknown, and length is what every candidate on every \
             build is sized and bounds-checked through",
        ),
        MemberSpec::new("pool_type", &[TYPE_POOL_HEADER], &["PoolType"]).required(
            "a paged allocation cannot be told from a non-paged or a freed one, so the sweep \
             would admit allocations the object it is looking for is never made from",
        ),
        MemberSpec::new("body", &[TYPE_OBJECT_HEADER], &["Body"]),
    ],
);
```

`_OBJECT_HEADER` and its `Body` are **not** required: a build whose table has no object
header at all still supports the tag sweep, and the constraints that need one are refused
individually, naming what is missing.

`TOP_DOWN_LAYOUT` declares `PointerCount` and `InfoMask`, both `required`, and is bound
only under `if top_down && object_header_size.is_some()` (`poolscan.rs:1064`). On a
bottom-up build `top_down_binding` is `None`, which says the question was never put. The
member that killed eight stages is still proved fatally — on the builds that read it, and
only there.

### A Linux stage, whole

`seance_plugin_memory_linux/src/lsmod.rs`:

```rust
pub const MODULE_LAYOUT: MemberSet = MemberSet::new(
    STAGE_LINUX_KERNEL_MODULES,
    &[
        TypeSpec::new("module", &["module"]).required(
            "no loaded kernel module can be described at all, so nothing can be said about what \
             was running in the kernel",
        ),
        TypeSpec::new("list_link", &["list_head"]).required(
            "the kernel's list links cannot be sized, so no module could be reached from the \
             modules list head",
        ),
    ],
    &[
        MemberSpec::new("list", &["module"], &["list"]).required(
            "a module structure has no link into the module list, so the list cannot be walked \
             and an empty result would read as a kernel with no modules loaded",
        ),
        MemberSpec::new("list_next", &["list_head"], &["next"]).required(
            "a list link has no forward pointer, so the module list cannot be walked at all",
        ),
        MemberSpec::new("name", &["module"], &["name"]),
        MemberSpec::new("state", &["module"], &["state"]),
        // `module_core`/`core_size` up to Linux 4.4; `core_layout` from 4.5.
        MemberSpec::new("core_base", &["module"], &["module_core", "core_layout.base"]),
        MemberSpec::new("core_size", &["module"], &["core_size", "core_layout.size"]),
        MemberSpec::new("init_base", &["module"], &["module_init", "init_layout.base"]),
        MemberSpec::new("init_size", &["module"], &["init_size", "init_layout.size"]),
        // Linux 6.4 replaced both layouts with an array indexed by an
        // enumeration. Declared so the stage can *say* the kernel uses that
        // shape rather than leave the size columns blank with no explanation.
        MemberSpec::new("module_memory", &["module"], &["mem"]),
        MemberSpec::new("taints", &["module"], &["taints"]),
        MemberSpec::new("args", &["module"], &["args"]),
        MemberSpec::new("version", &["module"], &["version"]),
        MemberSpec::new("srcversion", &["module"], &["srcversion"]),
    ],
);
```

Everything the walk cannot proceed without is `required` with a written consequence.
Everything else is a version difference stated as one, in the order the candidates should
be preferred. `mem` is declared purely so the stage can say *which* shape the kernel uses
rather than emit blank size columns.

`TASK_LAYOUT`, in the same crate's `tasks.rs`, shows the pattern at full stretch: `state`
became `__state` in Linux 5.14; `kuid_t` wrapped the id in a `val` member from Linux 3.5,
so `uid` is declared `&["uid.val", "uid"]` most-recent-first because the wrapped form must
not be read as an aggregate; `start_time` is a `timespec` of seconds on 3.2 and a `u64` of
nanoseconds from 4.11, and *which candidate resolved decides the unit, and the unit is
published*.

### Reading through the binding

Integers and pointers come straight off `BuildBinding::read_unsigned` / `read_pointer`.
`seance_plugin_memory_linux/src/read.rs` adds the shapes Linux needs that the binding does
not supply — fixed-length character arrays like `task_struct.comm` and `module.name`, and
C strings reached through a pointer — obeying the same rule, so no stage in that crate
re-derives "this build does not have that member" for itself.

## Where it is in use

| Crate | How |
|---|---|
| `seance_memory` | Home. `binding/`, re-exported from `lib.rs`. |
| `seance_plugin_memory_windows` | `poolscan.rs` declares `POOL_LAYOUT` + `TOP_DOWN_LAYOUT`. `process.rs` re-exports `Field`; `module.rs` re-exports `StageId`; `profile.rs` re-exports `Evidence`/`Found`; `vad.rs`, `psxview_threads.rs`, `modules.rs`, `hollow.rs`, `environment.rs`, `handles_token.rs`, `dump.rs` use `first_member`. |
| `seance_plugin_memory_linux` | Every stage that resolves its own structures declares a `MemberSet`: `tasks.rs`, `lsmod.rs`, `bash.rs`, `envars.rs`, `kernel_log.rs`, `lsof.rs`, `mounts.rs`, `proc_maps.rs`, `sockstat.rs`, `cmdline.rs` (`mm_struct.arg_start` / `arg_end`) and `hooks.rs` (`ftrace_ops` / `ftrace_ops_hash` / `ftrace_hash`, `kprobe`, `bpf_prog` / `bpf_prog_aux`, `idr` / `xa_node`, `module`), plus the shared `paths.rs` (which gained the `mount` / `vfsmount` / `fs_struct` members of the mount-crossing walk, bound by ordered candidates for the 3.3+ `struct mount` container and the pre-3.3 `vfsmount` shape). `read.rs`, `space.rs`, `error.rs`, `profile.rs`, `module.rs` build on it. (`capabilities.rs` reuses the task walk's binding rather than resolving one of its own.) |
| `seance_plugin_memory_macos` | `process.rs` declares `PROC_LAYOUT` + `TASK_LAYOUT`, `kext.rs` declares `KEXT_LAYOUT`, `fields.rs` reads through the binding. **Registered** under an unvalidated marker — see item 4 below. |

### Related, but a different question

This class answers *"which member name did this build use, and at what
offset?"* — a question about one structure inside a symbol table already
admitted. It does not answer **where the symbol table itself came from**, which
is `SymbolOrigin` on `LinuxBuild` (see
[LINUX_DESIGN.md](LINUX_DESIGN.md#tiers-12-in-practice-and-the-ordering-that-looks-backwards)).

The distinction matters because the two fail differently. A binding that
resolves the wrong member name produces a wrong offset in one stage. A symbol
table from the wrong source produces wrong offsets in *every* stage, and a
`BuildBinding` resolving cleanly against it says nothing at all about that —
it would resolve just as cleanly against a table describing a different kernel.
The binding records how a member was found; the origin records whether the map
it was found in should be trusted, and only the second reaches the report as a
qualification.

## How it was validated

Not by unit tests against a hand-written layout.

**Against the shapes that actually occur.** `binding/tests.rs` uses an XP-shaped
`_OBJECT_HEADER` (`NameInfoOffset`, no `InfoMask`), a `ucred` reaching its uid through an
embedded `cr_posix`, a capability set named `kernel_cap_struct` and not `kernel_cap_t`, a
name shadowed between base and user types, and a reference into a symbol table that was
never loaded — each taken from a real build difference.

**The fixture is itself guarded.**
`poolscan.rs::the_xp_fixture_declares_the_object_header_xp_had_and_not_a_later_one`
asserts the XP table has `NameInfoOffset`/`HandleInfoOffset`/`QuotaInfoOffset` and does
**not** have `InfoMask` or `TypeIndex`.

**The original failure has a regression test.**
`an_xp_build_is_describable_without_the_members_only_the_top_down_search_reads` builds an
XP profile and asserts `PoolSymbols::from_profile` succeeds, `top_down` is false, and the
sweep has everything it needs.
`a_member_this_build_lacks_is_recorded_as_absent_rather_than_failing_the_stage` strips
`_OBJECT_HEADER` entirely, asserts the sweep still runs, and asserts the layout record
carries `"kind": "not_declared"` with `"candidates": ["Body"]` — because a report that says
a value is absent has to say what was looked for.

**Against real evidence, with counts from the Volatility oracle.**
`seance_plugin_memory_linux/tests/parity_linux.rs` runs the whole tier against a 512 MiB
raw capture of Debian 7 (`3.2.0-4-amd64 #1 SMP Debian 3.2.57-3+deb7u2`) and asserts
Volatility 3's own row counts: `linux.pslist` 133, `linux.lsmod` 79, `linux.bash` 27,
`linux.envars` 1402. It also pins resolved offsets — `task_struct.tasks` at 368,
`comm` at 920 — because a `MemberSpec` lists candidates in preference order, so a
declaration naming the wrong candidate first still finds *something*, and a pid read out
of `p_ppid` is a plausible integer nothing downstream catches. Pinning the offset is what
makes a declaration falsifiable.

The image and symbols are not committed; the tests skip when `SEANCE_MEM_IMAGES` and
`SEANCE_SYMBOL_DIRS` are unset. Windows parity lives in
`seance_plugin_memory_windows/tests/parity_*.rs` against the XP and Windows 11 oracles.

| Image | Oracle |
|---|---|
| Windows XP | `~/forensic_images/memory/oracle/` — pslist 47, psscan 62, dlllist 1668, handles 9456, modules 127, malfind 100 |
| Windows 11 | `~/forensic_images/memory/oracle_win11/` — ldrmodules 5794, getsids 1511, handles 49665 |
| Linux | `~/forensic_images/memory/oracle_linux/` — elfs 2419, envars 1402, kmsg 1445, lsmod 79, check_syscall 661 |

Row counts are `wc -l` **minus 2** (header plus a trailing blank line).

## Beneath the binding: the translation and format layers

The binding answers *which member name, at what offset*. It sits on two layers it does not
own — address translation (`seance_memory/src/translate/`) and the acquisition-format
readers (`seance_memory/src/formats/`) — and a wrong answer from the layer beneath
looks, from a stage, exactly like a wrong binding.

**ARM64 translation is a primitive, not a tier (`ROADMAP` §3.8a, part).** `PagingMode`
had four variants and every one was Intel. It now has `PagingMode::Arm64(Arm64Regime)`,
where `Arm64Regime::new(granule, ttbr, va_bits)` is a checked `const` constructor:
`Arm64Granule` is `Kb4` / `Kb16` / `Kb64`, `Ttbr` is `Ttbr0` / `Ttbr1`, and `va_bits` is
bounded to 25..=48 (TxSZ 16..=39); 25..=52 for a regime built from a recorded `TCR_EL1` with `DS = 1` under a 16 KiB granule (LPA2). The level list is derived from granule and
width — start level, a narrowed top table, ARM's own level names — and verified to index
exactly the width for every granule × width × regime. With it the per-level flag
`PageLevel.large_page: bool` became `PageLevel.leaf: LeafRule` (`TableOnly` /
`IntelPageSize` / `IntelPage` / `Arm64Block` / `Arm64Page` / `Arm64TableOnly`) and the
walker and the downward enumeration both ask one classifier,
`PagingSpec::classify(entry, level) -> Option<EntryKind>` (`Invalid` / `Table` /
`Leaf { frame, size_log2, no_execute }` / `Unnameable { detail }`), instead of reading
bit 7, bit 1 or bit 12 themselves; the frame is masked from `MAXPHYADDR-1` down to the
level's remaining bits, never from a fixed 12. An oracle test restating the old Intel
line pins that Intel translation is unchanged. Each ARM64 regime is its own `PagingSpec`
/ `VirtualLayer`, canonical only in its own half; `no_execute` is PXN under TTBR1 and UXN
under TTBR0, OR'd with the hierarchical `PXNTable`/`UXNTable` of every table descriptor
above the leaf unless the regime records `TCR_EL1.HPDn = 1` (without FEAT_HPDS the bits
always apply) — and on Intel it is the leaf's XD OR'd with the XD of every non-leaf entry
above it (SDM Vol. 3A 4.6; a PAE PDPTE and 32-bit paging carry none); blocks are permitted at 4 KiB L1/L2 and 16/64 KiB L2 only, and descriptors
carrying FEAT_LPA/LPA2 output-address bits are refused as `AddressOverflow` rather than
masked — a table descriptor as much as a leaf, bits 49:48 under the 4 and 16 KiB granules
and bits 15:12 under 64 KiB. That refusal is only as wide as the descriptor shows: an LPA2
frame between 2^50 and 2^52 whose bits 49:48 are clear carries its high bits in 9:8, which
the non-LPA2 reading takes as the shareability field, so such a descriptor is read as a
48-bit frame and cannot be detected from the entry alone — no image records `TCR_EL1.DS`
or `ID_AA64MMFR0_EL1.PARange`, which would say whether the feature was on (a recorded
`TCR_EL1` with `DS = 1` under a 16 KiB granule is decoded as LPA2, `MEM-ARM-7`; under a 4 or 64 KiB granule it is refused by name). Top-byte ignore is honoured only for a regime
built from a recorded `TCR_EL1` whose `TBIn` is set: bits 63:56 are ignored, bit 55 still
selects the regime, and a regime built without one never untags — except where the caller
knows the operating system's fixed setting: `Arm64Regime::with_top_byte_ignore` sets it, and
Linux discovery does so for every process (TTBR0) space, because Linux arm64 sets `TBI0`
unconditionally. `APTable` is not read,
because no access permission of any level is reported and no consumer exists to read the bits. What is deliberately **not** there: under `PteSemantics::Linux` an ARM64
non-valid entry is `NotPresent`, never a swap entry — the present-invalid marker moved
between bit 58 and bit 11 across kernel series and each is a swap-offset bit under the
other layout, so a swapped page and a `PROT_NONE` page cannot be told apart from the
descriptor; under `PteSemantics::Windows` an ARM64 spec reads a valid-clear descriptor as Windows 11 ARM64 builds 28000 and
26300 both lay it out (`MEM-ARM-8`, `MEM-ARM-11`; Microsoft's PDBs, checked on two QEMU-emulated captures): `Prototype` bit 10
(named, not followed), `Transition` bit 11 (read as a standby page) and `PageFileHigh` bits 63:32. `PageFileLow` is bits 17:14 on 28000
and bits 9:6 on 26300 and the spec is not told the build, so **no pagefile index is stated on ARM64**. Two builds were read; no other. **Every ARM64
fixture is synthetic**, written from ARM DDI 0487 D8.3, and no Linux or Windows discovery
sits on the primitive, so no ARM64 image is analysed end to end. The core
has also walked real page tables — two **QEMU-emulated** AArch64 Linux guests from the
MMUShell dataset, 4 KiB granule, 39- and 48-bit regimes, from the `TTBR`/`TCR` values the
emulator recorded — and all 11,663 leaves of the four trees agree with an independent walker
(`seance_memory/tests/arm64_mmushell_real_test.rs`, `VALIDATION.md` MEM-ARM-1). That is
emulated, not hardware; the roots were handed in, not discovered; and 16/64 KiB granules,
LPA2 and non-zero invalid descriptors were not in that evidence. The 16 and
64 KiB granules agreed with the same independent walker on every leaf of a
QEMU-booted Debian 16 KiB and Ubuntu 64 KiB kernel (`VALIDATION.md` `MEM-ARM-5`/`6`);
LPA2 and non-zero invalid descriptors had no evidence in that run. LPA2 under the 16 KiB granule agreed with the same walker on every leaf of a QEMU-booted `-cpu max` kernel (`MEM-ARM-7`; the captured tables have every address bit above 47 clear, so the high-bit decode is pinned on synthetic tables from the manual), and non-zero invalid descriptors have no evidence.
`Arm64Regime::from_tcr_el1` builds a regime from a raw `TCR_EL1` (granule per `TG0`/`TG1`,
whose encodings differ; width; `IPS`; `TBIn`; `HPDn`; `EPDn`), refusing `DS = 1` under a 4 or 64 KiB granule (it is decoded under a 16 KiB one), a reserved
`TG`, a `TxSZ` outside 16..=39 and `IPS = 0b111`; an output address above `IPS` — a table's or
a leaf's — is an Address size fault refused with the entry verbatim (`AddressOverflow` /
`Blindness::Unnameable`), and a regime built with `new` enforces the 48-bit descriptor width
only. The corpus test builds its regimes through that constructor. Linux discovery offers the arm64 kernel regimes to
its banner proof (see `LINUX_DESIGN.md`), so the sentence above that no discovery sits on the
primitive is true for Windows only. The layer metadata names the regime (`paging_mode` such as
`arm64_4k_ttbr1`, `arm64_granule`, `arm64_ttbr`, `arm64_va_bits`,
`min_virtual_address`), so a binding resolved against an ARM64 space will say which
space it was.

**Two `UnsupportedArchitecture` gates, one per tier, and they key on different
evidence.** The Windows tier's `automagic::discover_reported` refuses, before any DTB
sweep, an image whose **acquisition header** states a non-Intel machine (a crash dump
does; the layer publishes it) — `DiscoveryError::UnsupportedArchitecture { architecture,
detail }`, worded as a limit of this tool and not an absence of a kernel, and
`automagic_dtb::rules_for` returns `None` under `PagingMode::Arm64` so no Intel
self-reference rule is borrowed. A **raw** image states no architecture and is swept as
it always was; an ARM64 raw image therefore still ends at `NoDirectoryTableBase`, which
is honest but less specific. The Linux tier's gate keys on the **symbol table** admitted
for the banner: a table declaring non-8-byte pointers, or one the admission gate's
architecture check refused, is `discovery::DiscoveryError::UnsupportedArchitecture {
banner, reason }`, whose text says the tier reads 64-bit x86 paging (four- and five-level)
and arm64 paging with 4 KiB pages (39- and 48-bit). An **arm64** kernel's table declares 8-byte pointers and passes both, so
an arm64 Linux capture does not reach that gate. Discovery offers the
Intel depths and the seven arm64 kernel (`TTBR1`) regimes to the banner proof
(`discovery::PAGING_MODES`, narrowed by `discovery::modes_for` when the table declares
`kimage_voffset` or an x86-64-only symbol). An arm64 kernel that proves under no regime
this build decodes is `UnsupportedArchitecture` naming arm64 **when the symbol table or the
image's own `VMCOREINFO` says arm64**. A kernel that proves under a 16 or 64 KiB granule is
profiled, not refused, because the stages take the page shift from the regime.
An unhinted image that proves in both
families is `ArchitectureUndetermined` unless an agreed `VMCOREINFO` names one of them,
and an Intel-only proof is not taken while any `VMCOREINFO` copy found names arm64, even in
a sweep that was cut short or whose copies disagree. With nothing naming arm64 it still ends at
`PageTablesUnproved` (`LINUX_DESIGN.md`, "ARM64 discovery"). Neither gate is a
`BindError`; both fire before a `MemberSet` is ever resolved.

**The hibernation reader's table header.** `formats/hibernation.rs`
reads the packed restore-table header's compressed-size field as
**21** bits (`TABLE_SIZE_MASK = 0x1F_FFFF`), and bit 29 is a flag whose meaning is not
established (set on 15,326 of the 31,969 kernel tables of the 26200 corpus; recorded as
`uninterpreted`, both classes decoding with the same codec). Read as size, bit 29 stepped
the walk into compressed data 4.3 MB into the kernel set. The Xpress-Huffman flag is read
**per header layout**: bit 30 on NT10 (`TABLE_HUFFMAN_NT10`; 30,479 of the 26200 kernel
tables), bit 31 on NT6.2/6.3 (`TABLE_HUFFMAN_NT62`), where bit 30 alone is plain
`XpressMax`. A restore set has no
terminator, so each set's described page count is checked against the header's own
count (`0x58` for the boot set, `0x238` for the kernel set) and `UnresolvedStructure` is
stated only when they disagree; a block yields every byte of its pages or is a counted gap.
Measured on the corpus: both sets complete, 2,258,956,288 bytes, all 65,536 marker pages
byte-exact (`VALIDATION.md` `HIB-1`).

## What is NOT this class

A sweep must not churn these:

- `first_member(...)` — the correct low-level idiom.
- `has_member(...)` guards — already correct.
- `.member_offset(...).is_ok()` / `.ok()` dispatch — already correct.
- **Deliberate whole-stage refusals with a written reason.**
  `netscan.rs::require_supported_build` refuses `major < FIRST_MODERN_TCPIP_MAJOR`, naming
  `_ADDRESS_OBJECT` / `_TCPT_OBJECT` and stating *"This is not an absence of network
  activity."* That is an honest refusal of a decoder this stage does not have, and **it
  must stay fatal**. Degrading it would be a regression. (`NetworkPlan` routes
  pre-Vista builds to `netscan_legacy`, which does decode those objects, so reaching that
  arm means a caller asked the *modern* decoder for a pre-Vista image — and the answer
  to that is unchanged.) `Necessity::Required` exists for exactly that case, and `bash.rs`
  proves the point in a test: the maple-tree refusal's `without_it` must contain *"limit of
  this tool"*, because a tool limit must never be phrased as a finding about the machine.

## What is still outstanding

**1. The compiler catches the defect shape.**
`StructReader::member_offset` returns `MemberOffset` and `StructReader::size_of` returns
`TypeSize`. Both are `#[must_use]`, and that is the whole point of the newtypes — they
carry no other behaviour.

Reintroducing the original line produces `unused MemberOffset that must be used`,
and CI runs `cargo clippy -- -D warnings`, so it fails the build rather than waiting for
review. Verified by reintroducing it, not by assuming.

Two newtypes rather than one, so an offset and a size cannot be added together without
saying so; and `bytes()` rather than a `Deref<Target = u64>`, so the value cannot slip
back into arithmetic without a decision.

What the compiler still does not judge is whether a bound-and-read offset *should* have
been a `MemberSet` declaration. An offset read on every branch is correct; one read only
under a branch some builds never take is what this document is about. That reading is
still a human job.

**2. Layout records.**
Every Linux stage that resolves a binding now puts `BuildBinding::to_json` on its
artifact under `"layout"`: `tasks.rs`, `lsmod.rs`, `bash.rs`, `envars.rs`,
`kernel_log.rs`, `lsof.rs`, `mounts.rs`, `sockstat.rs`, `proc_maps.rs`, `cmdline.rs` and
`hooks.rs` — eleven of the twelve stages (`capabilities` reuses the task walk's binding
rather than resolving one of its own). Verified by
`grep -n '"layout"' seance_plugin_memory_linux/src/*.rs`, which returns eleven files.

**The Windows half of this item is open.** In that tier only `poolscan` emits one, via
`PoolSymbols::layout_json`; every other Windows stage uses the low-level `first_member`
idiom, which is correct but publishes no per-stage layout record. Several Windows stages
do emit a `"layout"` key — `services.rs` its hand-catalogued `ServiceLayout`, and
`netscan.rs`, `dump.rs` and `amcache_shim.rs` structures of their own — but none of those
is a `BuildBinding`, so none of them says which candidate name a member resolved under.
`grep -rn 'BuildBinding\|MemberSet' seance_plugin_memory_windows/src/` returns
`poolscan.rs` and nothing else.

The `tamper_checks` stage's groups publish a
layout record of their own shape rather than a `BuildBinding`, and they are
worth naming here because of what each decided:

* `tamper_unloaded.rs` reads a record layout the ISF mostly **does not
  declare** — 46 of the 1,724 `ntkrnlmp.pdb` ISFs on this machine declare
  `_UNLOADED_DRIVERS`, and all 46 agree exactly. So the x64 fallback is carried
  as this project's own table, *validated against those 46*, and named on every
  record (`record_layout`: `isf` / `documented_x64` / `documented_x86`) with its
  basis beside it. No x86 ISF declares the type at all, so records read through
  the x86 fallback are stamped `unvalidated`. On two x86 builds —
  XP SP2 and SP3, four real captures — the x86 fallback's names, ranges and slot
  order agree with Volatility 3's `windows.unloadedmodules` exactly. The stamp
  stays, because two builds are not the x86 pack (`VALIDATION.md` MEM-XP-2). A declared type that is not the
  record — Volatility's bundled layout declares the array container — is
  refused with the refusal stated, rather than a stride being taken from a
  container's size.
* `tamper_timers.rs` resolves every offset per build and publishes them under
  `"layout"` with the basis for each. Its one new primitive is
  `seance_memory::object::StructReader::array_shape`, because
  `_KTIMER_TABLE.TimerEntries` is declared `[2][256]` on build 26200 and
  `[256]` on the 1,233 older ISFs that declare it: a bucket count must be the
  **product** of the declared dimensions, and reading the outer one walks 2 of
  512 buckets with nothing in the result looking wrong. For the legacy global
  table two more facts come from the symbols rather than from a constant: where no `_KTIMER_TABLE_ENTRY` is
  declared (349 of the 926 legacy-shape ISFs across the four kernel names) the
  bucket is a bare `_LIST_ENTRY` and the stride is that type's declared size;
  and the extent the bytes suggest is bounded by the **next symbol the build
  declares** above `KiTimerTableListHead` — on XP that is
  `KiDispatcherReadyListHead` at +2,048, whose 32 list heads the heads-only
  probe had read as buckets 256–287. `_KTIMER.Period` is `long` on XP and
  `unsigned long` later, so it is read through `Obj::int`, which carries the
  declared signedness. A member's declared **type**
  is not always what it holds: `_KTIMER.Dpc` is declared a pointer to `_KDPC`
  on every build, and on an x64 build that declares `KiWaitNever` and
  `KiWaitAlways` (1,059 of the 3,015 kernel ISFs in the pack) it holds an
  encoded value. Whether to decode is bound to the build (both keys declared,
  64-bit), and each decoded pointer is checked against the build's own
  `_KDPC.Type` offset and `_KOBJECTS.DpcObject`/`ThreadedDpcObject` values —
  54 key-declaring ISFs lack those, and on them no DPC is read at all. Reading
  the declared type literally panicked the pipeline on Server 2012 R2 and
  published encoded values as addresses on every such build.

* `tamper_threads.rs` resolves every member through `first_member` — the
  low-level idiom this document prescribes — and publishes the **paths it
  resolved** under `"symbols"`, which is the part a `BuildBinding` would add.
  It is worth recording why the idiom earns its keep here: `_KTHREAD.SystemThread`
  is a bitfield whose bit position is 10, 11, 12 or 13 and whose offset is 60,
  76 or 116 across the pack, and it is **absent on 650 of the 1,724 ISFs** —
  where absent, the group falls back to the owning process being
  `PsInitialSystemProcess` and each row says which test answered. A
  `has_member`-based check would have answered "false" for a table that merely
  could not disambiguate the name, which is the collapse `first_member` exists
  to prevent. The same idiom finds the NT 5.x spelling of the debug flag:
  XP declares `_KTHREAD.DebugActive` (a byte at 0x2c) and no
  `_DISPATCHER_HEADER.DebugActive`, so `Tcb.DebugActive` is the third
  candidate. And a member's **width** is part of the binding as
  much as its offset: the `Dr` registers are `unsigned long` on x86, and a
  fixed eight-byte read at the declared offsets glues `Dr1:Dr0` into one value,
  so they are read through `Obj::unsigned` at the declared width. And a **bitfield's position** is part of the binding too: where `_DISPATCHER_HEADER.ActiveDR7` is declared
  it is one bit of the `DebugActive` byte (bit 0 on the Windows 10 ISFs, beside
  `Instrumented` at bit 1), so the debug-register confirmation reads that
  bitfield through the table's own extraction and never the whole byte.

None is a `BuildBinding`, so the item above stands: what they publish says
which offsets were used, not which candidate *name* each member resolved
under.

A
member's declared offset is not by itself enough to read it: `_KTRAP_FRAME.Dr0`
shares offset 216 with `ShadowStackFrame` on Windows 11 26200, and `Dr1` shares
224 with `Spare[5]`. The ISF format flattens a union, so **two names at one
offset is a legitimate declaration and the symbol table cannot say which is
live**. Only the structure's own state can — here `_DISPATCHER_HEADER.DebugActive`
/ `ActiveDR7` — and, on a build that declares `ActiveDR7`, that bit alone, since
the rest of the `DebugActive` byte is other flags. A binding that resolves cleanly and reads the offset it was given
still produced five false armed breakpoints on a clean capture. Where a member
overlaps another, the discriminator is part of what must be bound.

**3. Linux capabilities.**
`STAGE_LINUX_CAPABILITIES` (`capabilities.rs`) decodes each process's effective,
permitted, inheritable, bounding and ambient sets to named capabilities. It reuses the
`pslist` task walk and therefore reports the same 133 processes on the Debian 3.2 sample,
pinned by `parity_linux.rs`
(`"linux.capabilities reuses the pslist task walk, which reports 133"`, and
`json["count"] == 133` with `json["complete"] == true`) — against Volatility's **one row
and an error** on that same image, which is the motivating example this document opens
with.

The Linux tier runs **twelve** stages: processes, capabilities, kernel modules, kernel
log, process maps, open files, network sockets, mounts, bash history, environment,
command lines and kernel hooks. See `documentation/LINUX_DESIGN.md` for the table.

**4. The macOS tier is registered and unvalidated.** The paragraphs below give what is
established for the tier, what is not, and the symbol-pack coverage. The tier is
registered in `seance_api/src/modules.rs` immediately after the Linux tier, and
`seance_api/src/memory.rs` folds its record types into the coverage rows that count them.

Withholding the tier would make a Mac capture *silent*,
and silence reads as "nothing was running" — the one claim that is never safe. An examiner
can discount a result labelled unvalidated; they cannot discount a result they were never
shown. Every artifact still carries `validated_against_real_capture: false` plus a
validation state and notice, applied last by a single private `stamp()`, and those markers
survive the trip through the API rather than sitting in a metadata blob only the raw
record endpoint serves. An image with no Darwin banner produces zero artifacts, so no
Windows or Linux capture grows a spurious macOS failure.
`seance_api::modules::tests::the_macos_tier_is_registered_under_a_marker_that_says_it_is_unvalidated`
pins both halves, so nobody can register-and-unmark without validating.

A real
capture and oracle are still wanted, the route to one (a suspended VMware Fusion guest,
whose `.vmem`/`.vmss` pair `seance_memory::formats::vmware` already reads) is still the
right route, and until it exists the marker is what stands between an examiner and an
unqualified claim.

`seance_plugin_memory_macos` is a
workspace member, and its tests run against Apple's shipped 10.12.3 KDK
(`tests/kdk_symbols.rs`, xnu-3789.41.3~3, 4,839 types, 43,548 symbols) wherever that kit
is on disk, skipping where it is not, since `reference/` is gitignored. Membership means
the code cannot rot silently.

What is established for that tier: Apple's symbols pass the admission gate; the banner is
where it expects; every member `PROC_LAYOUT` marks `Required` exists on xnu-3789 and
resolves to the offset the kernel uses (`p_pid` 16, `p_ppid` 40, `p_uid` 48, `p_gid` 52,
`p_stat` 104, `p_comm` 740, `p_list` 0, `proclist.lh_first` 0, `proc` size 1144; `task.tasks`
40, `task.bsd_info` 896, size 1360; the ten `kmod_info` members); the `allproc` walk, a
2 MiB kernel slide, a link into unacquired memory, and 4 KiB / 2 MiB / 1 GiB page
translation, all against synthetic memory laid out at real geometry.

**Not established: a real capture.** No page-table hierarchy built by a live kernel, no
compressed or swapped regions (macOS uses a memory compressor rather than a pagefile, and
that decoder is not written), and no process the fixture did not itself place. Every
record the tier would emit carries `validated_against_real_capture: false`, because a
process list produced by unvalidated code looks exactly like one produced by code run
against a hundred images.

The route to a real capture and a matching oracle
is to generate it rather than find it: `seance_memory`'s `formats/vmware.rs` already reads
`.vmem` plus `.vmss`/`.vmsn` snapshot pairs including the `regionPPN` / `regionPageNum` /
`regionSize` region table, so macOS 10.13 or 10.14 running as a VMware Fusion guest on
Intel hardware, suspended, yields a genuine memory image in a format this tree already
parses — and, unlike a downloaded sample, a **known ground truth** captured alongside it
(`ps -axo pid,ppid,uid,lstart,comm`, `kextstat`, `netstat`).

Coverage of the packs that do exist: 129 real KDK packs, 10.6.4 to 10.15.4, **x86 only**.
No Big Sur, no macOS 12-15, no Apple Silicon. Twelve packs (10.6.4-10.7.5) are 32-bit and
carry no `version.constant_data`, and the banner symbol is the only macOS identification
path, so those twelve can never be selected: the `IsfOs::Linux | IsfOs::Mac` arm of
`seance_symbols/src/identify.rs` (~189-198) resolves both a missing banner symbol and a
banner symbol with no constant bytes to `identifier: None` with `IdentifierSource::None`. Volatility 3 cannot
load them either, since its mac stacker requires `BootPML4`, which those packs lack. And
`reference/` is gitignored, so the 85 MB exists on one machine and CI has never seen it.
