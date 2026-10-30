# `seance_hive` against `nt-hive` 0.3.0

The crate this one replaced is `nt-hive` by Colin Finck, GPL-2.0-or-later. This
document records what the two do differently, measured rather than asserted.

**Provenance.** `seance_hive` was written from Maxim Suhanov's *Windows registry
file format specification* (CC BY 4.0) and pushed before anyone here read a line
of `nt-hive`'s implementation. Its source was read afterwards, once, to write
this comparison. Nothing was copied from it, and nothing in `seance_hive` has
been changed in response to reading it — where this document names a difference
in our favour it was already there, and where it names one against us the fix,
if any, comes from the specification.

**How the differential was run.** A harness outside this repository links both
readers, walks every key and value of the same bytes with each, and compares the
key paths, the value names, types, lengths and bytes. It is not shipped: linking
a GPL crate into a distributed artefact is the thing this replacement exists to
avoid. Method and results, on the `plaso` test corpus.

## Do they read the same thing?

Five real hives, walked completely with both:

| Hive | Version | Keys | Values | Agreement |
|---|--:|--:|--:|---|
| `NTUSER.DAT` | 1.3 | 1,127 | 5,601 / **5,602** | keys identical; one value only we read |
| `NTUSER-WIN7.DAT` | 1.3 | 2,288 | 5,469 / **5,470** | keys identical; one value only we read |
| `NTUSER-CCLEANER.DAT` | 1.3 | 1,203 | 2,372 / **2,373** | keys identical; one value only we read |
| `SAM` | 1.3 | 65 | 70 | identical bytes; data **types** differ, below |
| `SYSTEM` | 1.5 | 30,756 | 73,455 | **identical** |
| `SOFTWARE` | 1.5 | 117,488 | 193,870 | **identical**, 11,155,714 data bytes each |

Key trees agree exactly everywhere, including 117,488 keys in a 37 MB
`SOFTWARE`. Two substantive differences came out of it, both in this reader's
favour, and one performance difference against it.

### 1. A large value in a version 1.3 hive: `nt-hive` loses it

`NTUSER.DAT` holds `Software\…\Explorer\StartPage\ProgramsCache`, a 19,242-byte
`REG_BINARY`. `nt-hive` returns an error for it; this reader returns the bytes.
plaso's own test suite parses that value into 27 shell items, so the value is
real, and the same three NTUSER hives each lose one value the same way.

The cause is a dispatch on size alone. Big data (`db`) is defined for values
over 16,344 bytes **when the minor version is above 3**; below that, a large
value is stored in one large cell. `nt-hive` treats any value over 16,344 bytes
as big data and fails when it finds no `db` record there. This reader requires
**both** the size and the `db` signature before taking the big-data path, so the
single-cell form of a 1.3 hive reads correctly through the same code.

Verified independently: a third implementation of just that path, written in
Python from the specification, reads the value from a single 32,764-byte cell
and produces bytes identical to ours (19,242 bytes, FNV-1a
`0x113720aac7748e9b`).

This matters beyond one value. `NTUSER.DAT` is a 1.3 hive, and 1.3 covers
Windows NT 4 through XP — every value above 16 KB in every XP-era user hive is
affected.

### 2. Unknown data types: `nt-hive` discards the number

The `SAM` hive stores each account's RID in the **data type** field of the value
under `Users\Names\<account>` — a type code of 500 for `Administrator`, 501 for
`Guest`, 1000 for a created user, 513 for the `None` group. These are not
registry data types, and both readers correctly decline to name them.

`nt-hive` reports them all as a bare `Unknown`. This reader reports
`Unknown(500)`, `Unknown(501)`, `Unknown(1000)`, `Unknown(513)` — the number
that was there. On this hive that is the difference between reading four account
RIDs out of `SAM` and reading none of them.

### 3. Speed: `nt-hive` is faster

| Hive | `nt-hive` | `seance_hive` | Ratio |
|---|--:|--:|--:|
| `SYSTEM`, 15.9 MB | 3.12 ms | 5.02 ms | 1.61× |
| `SOFTWARE`, 37.7 MB | 14.64 ms | 19.68 ms | 1.34× |

A full walk — every key, every value, every byte of data — opened without
validation, median of 301 interleaved runs of each reader in one release
binary. Both readers agree on the counts (`SYSTEM` 30,756 keys,
73,455 values, 4,633,357 data bytes; `SOFTWARE` 117,488 / 193,870 /
11,155,714). The machine was shared and loaded (load average ≈ 17 on 16
cores), so absolute times drift by up to 2× between repeats; the
columns come from the same interleaved run and it is their ratios, not the
milliseconds, that carry.

This reader reads a leaf index (`lf`, `lh`, `li`) in place with no allocation
(pinned by `tests/subkey_leaf_alloc.rs`) and resolves only an `ri` up front,
because that walk carries the depth bound and the unresolved-sublist record
described below. The subkey list is not what the gap is. The cause is not
diagnosed. `nt-hive` is a `no_std` crate written for a
bootloader; the per-value and per-name checks this reader makes are the
likeliest place to look, and at 20 ms for 37 MB nothing waits on it.

The `ri` question is settled by counting. Scanning the allocated
cells of the same hives finds 7 `ri` records in `SOFTWARE` (117,488 keys; sublist
counts 8, 2, 4, 6, 12, 2, 14) and 2 in `SYSTEM` (30,756 keys; counts 4, 5). Resolving
them eagerly touches about fifty sublists in the whole walk, so it cannot account
for a 1.34x or 1.61x gap, and making it lazy would move nothing. It stays eager by
design: it carries the depth bound (`MAX_INDEX_DEPTH`) and the unresolved-sublist
record that `layered.rs` and the registry plugin report as incompleteness, and a lazy
form would need a pre-pass to keep `listed_len` known. The gap itself is
undiagnosed; per-value and per-name checks remain the likeliest cause.

## Robustness

3,000 mutated copies of `NTUSER.DAT` (1–16 random byte flips each), walked
completely by both:

| | `nt-hive` | `seance_hive` |
|---|--:|--:|
| Panics | **2** | **0** |
| Read cleanly | 2,998 | 3,000 |
| Disagreements where both read | 0 | — |

Both panics are the same assertion, `hive.rs:117`:
`assert!(data_offset != u32::MAX)` — an offset field of all-ones reaching a
function that requires a real offset. In this reader `0xFFFFFFFF` means "no such
structure" at every field that can hold it, and any other unusable offset is a
`CellOutOfBounds` error.

That is with the copy this project had already patched twice for panics it hit
in the field. Upstream, unpatched, the count would be higher. A parser fed carved fragments and unallocated space
is the wrong place for a debug assertion on attacker-controlled data, which is
why every bound in this reader is an error and the crate's own test suite
includes 64 random buffers behind a valid header.

`nt-hive` is nonetheless careful code: it forbids `unsafe`, uses checked
arithmetic, and validates each structure's signature and size before reading it.
Both readers survived 2,998 of 3,000 hostile inputs identically.

## Specification adherence, both readers

Against Suhanov's specification, field by field. `seance_hive`'s own
cross-check is in [SPEC_CROSSCHECK.md](SPEC_CROSSCHECK.md).

| Point | `nt-hive` 0.3.0 | `seance_hive` |
|---|---|---|
| Base block fields and offsets | correct | correct |
| Checksum, including the 0 → 1 and −1 → −2 rule | correct | correct |
| Minor version accepted | **≥ 3, no upper bound** — refuses NT 3.x (1, 2), accepts 99 | **1–6** — reads NT 3.x, refuses what it was not written against |
| Clustering factor | **must be 1** — refuses a 4K-sector hive | 1, 2, 4 or 8, the values the definition can produce |
| Declared data size: alignment, bound | correct | correct |
| Cell sign, 8-byte alignment, bounds | correct | correct |
| Key node fields | correct | correct |
| Subkey index `lf`, `lh`, `li` | correct | correct |
| Subkey index `ri` | correct, and **nested `ri` refused outright** | correct, nesting bounded at 8 levels |
| Value fields, inline-data rule | correct | correct, and an inline size above 4 is refused as corrupt |
| Big data `db` | **dispatches on size alone** — wrong on 1.3 hives (§1) | size **and** signature |
| Unknown data type codes | collapsed to `Unknown` (§2) | `Unknown(code)` |
| Name encodings, compressed-name flags | correct | correct |
| Case-insensitive name lookup | full Basic Multilingual Plane, via a generated table | **none**; callers enumerate |
| Hive bin headers | not validated | not validated |
| `sk` security cells | **the cell, its ring, its reference count and the descriptor bytes** — read; decoded by `seance_core::secdesc` | not implemented |
| Log replay, deleted cells | not implemented | not implemented |

Two rows favour `nt-hive`. It offers a name lookup with complete case folding
where this reader offers none, because nothing in Séance looks up by name and a lookup that is
wrong on non-ASCII names is worse than enumeration. And its open-ended upper version bound will read
a future 1.7 hive where this one refuses it; that is a real trade, taken
deliberately, because reading a layout this code was not written against
produces records nobody could stand over.

## Size and shape

| | `nt-hive` 0.3.0 | `seance_hive` |
|---|--:|--:|
| Source lines | 4,830 | **1,327** |
| Of which one generated Unicode table | 1,546 | 0 |
| Dependencies | 5 (`zerocopy`, `bitflags`, `enumn`, `memoffset`, `thiserror`) | **0** |
| `unsafe` | forbidden | forbidden |
| Tests in the crate | 11 | **27** (plus a spec-offset suite) |
| `no_std` | yes | no |
| In-place mutation | `clear_volatile_subkeys`, for booting a hive | none |
| Licence | GPL-2.0-or-later | MIT |

The line counts are not a like-for-like judgement: a third of `nt-hive` is a
generated case-folding table for a lookup path this project does not use, and it
carries `no_std` support and the mutation a bootloader needs. Between the two,
the reading code is of a similar size.

## What this reader does that the other could not

Beyond the two correctness differences, `nt-hive` keeps the key node's
last-write time, subkey count and value count private with no accessor. This
reader exposes all three, and `seance_plugin_registry` writes them onto
every key record — the difference between a key inventory that can distinguish a
key written during an incident from one written at install, and one that
cannot.
