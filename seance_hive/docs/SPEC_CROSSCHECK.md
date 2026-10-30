# Cross-check against the format specification

Every structure this crate reads, checked field by field against Maxim
Suhanov's [*Windows registry file format
specification*](https://github.com/msuhanov/regf) (CC BY 4.0), which is what it
was written from. Offsets are given in decimal, as that document gives them.

Where this reader deviates, the deviation is in this table with the reason. The
numbers below are also asserted in code — `src/tests/spec_tests.rs` builds
buffers at exactly these offsets — so a drift fails a test rather than a case.

Checked on 2026-09-13 against the specification as published at that date.

## Base block — 4096 bytes

| Offset | Size | Field | Read as | Status |
|--:|--:|---|---|---|
| 0 | 4 | Signature `regf` | `Hive::without_validation` | ✅ |
| 4 | 4 | Primary sequence number | `sequence_numbers().0` | ✅ |
| 8 | 4 | Secondary sequence number | `sequence_numbers().1` | ✅ |
| 12 | 8 | Last written timestamp (FILETIME) | `last_written_filetime()` | ✅ |
| 20 | 4 | Major version | `major_version()`, must be 1 | ✅ |
| 24 | 4 | Minor version | `minor_version()` | ⚠️ see below |
| 28 | 4 | File type (0 = primary) | `file_type()`, must be 0 | ✅ |
| 32 | 4 | File format (1 = direct memory load) | `file_format()`, must be 1 | ✅ |
| 36 | 4 | Root cell offset | `root_cell_offset()` | ✅ |
| 40 | 4 | Hive bins data size | `declared_data_size()` | ✅ |
| 44 | 4 | Clustering factor | `clustering_factor()` | ⚠️ see below |
| 508 | 4 | Checksum (XOR-32 of the first 508 bytes) | `computed_checksum()` | ✅ |

The checksum rule — *"if result equals -1, set to -2; if 0, set to 1"* — is
implemented and tested in both directions, so a checksum field of 0 or all-ones
can never verify.

**⚠️ Minor version.** The specification lists 3, 4, 5 and 6 for a primary file.
This reader accepts **1 to 6**. Versions 1 and 2 are NT 3.x hives, whose
structures are the ones below; refusing them would lose every key in such a
hive to a version number rather than to anything unreadable. Outside that range
the answer is a refusal, because the layout would no longer be one this code
was written against.

**⚠️ Clustering factor.** Defined as the logical sector size divided by 512, so
1, 2, 4 or 8. Windows writes 1. This reader accepts **1, 2, 4 or 8** and
refuses anything else. It changes nothing about how the structures below are
read — hive bins are 4096-aligned either way — so the check exists only to
reject a buffer that is not a base block, and is deliberately not narrowed to
1: refusing a hive from a 4K-native disk would be a lost case over a field this
code does not use.

## Hive bin header — 32 bytes

| Offset | Size | Field | Status |
|--:|--:|---|---|
| 0 | 4 | Signature `hbin` | ⚠️ not validated |
| 4 | 4 | Offset, relative to hive-bin data | ⚠️ not read |
| 8 | 4 | Size, a multiple of 4096 | ⚠️ not read |
| 20 | 8 | Timestamp (first bin only) | ⚠️ not read |

**⚠️ Deliberate.** Cells are addressed from the start of the hive-bin data, not
through their bin, so this reader never needs a bin header. Validating them
would turn a hive with one damaged bin header into a hive with no readable
keys, which is the wrong trade for evidence. The cost is that a cell offset
landing in the middle of a damaged region is caught by the cell's own checks
rather than by its bin's — and those checks are the ones that bound every read.

## Cell

*"Size of a current cell in bytes, including this field (aligned to 8 bytes):
the size is positive if a cell is unallocated or negative if a cell is
allocated."*

Implemented in `Hive::cell_data`: the sign decides allocation, the magnitude is
required to be at least 8 and a multiple of 8, and the cell must fit inside the
hive-bin data **the buffer actually holds** — never inside what the base block
claims. That last point is what lets a truncated acquisition read up to the cut
and no further. ✅

## Key node (`nk`)

| Offset | Size | Field | Read as | Status |
|--:|--:|---|---|---|
| 0 | 2 | Signature `nk` | checked | ✅ |
| 2 | 2 | Flags | `flags()` | ✅ |
| 4 | 8 | Last written timestamp | `last_written_filetime()` | ✅ |
| 12 | 1 | Access bits (Windows 8+) | — | not read |
| 13 | 1 | Layered key bit fields (minor 6): bits 0-1 layer semantics, bit 7 inherit class | `layered_key_bits()`, `None` below minor 6 | ✅ (see *Layered keys* below) |
| 14 | 2 | Spare | — | not read |
| 16 | 4 | Parent | `parent_offset()`, `0xFFFFFFFF` → `None` | ✅ |
| 20 | 4 | Number of subkeys | `subkey_count()` | ✅ |
| 24 | 4 | Number of volatile subkeys | — | not read, see below |
| 28 | 4 | Subkeys list offset | `subkeys()` | ✅ |
| 32 | 4 | Volatile subkeys list offset | — | not read, see below |
| 36 | 4 | Number of key values | `value_count()` | ✅ |
| 40 | 4 | Key values list offset | `values()` | ✅ |
| 44 | 4 | Key security offset | `security_offset()`, `security()`, `0xFFFFFFFF` → `None` | ✅ |
| 48 | 4 | Class name offset | `class_name()` | ✅ |
| 52–68 | 20 | Largest-name caches, WorkVar | — | not read (caches, not evidence) |
| 72 | 2 | Key name length | `name()` | ✅ |
| 74 | 2 | Class name length | `class_name()` | ✅ |
| 76 | n | Key name | `name()` | ✅ |

Fixed size 76 bytes before the name, matching the offset the name starts at.

**Volatile subkeys are not read, and that is correct for this use.** They exist
only in a hive loaded into a running kernel; a hive read from a disk image or a
file has none, and the offset field in such a file points at memory that is not
in the file. Reading it would produce cells from whatever happened to be at
that offset.

**The counts are advisory; the lists are authoritative.** A key declaring three
subkeys with no list offset yields no subkeys rather than an error — a count
with nothing behind it is exactly the shape a damaged hive has, and the list is
what can actually be walked.

### Flags (offset 2)

| Value | Meaning | Status |
|--:|---|---|
| 0x0004 | `KEY_HIVE_ENTRY` — the root key | read, not required |
| 0x0008 | `KEY_NO_DELETE` | not read |
| 0x0010 | `KEY_SYM_LINK` | not read |
| 0x0020 | `KEY_COMP_NAME` — name is one byte per character | ✅ used |
| 0x0080–0x0200 | Virtualisation flags (Vista+) | not read |

## Key value (`vk`)

| Offset | Size | Field | Read as | Status |
|--:|--:|---|---|---|
| 0 | 2 | Signature `vk` | checked | ✅ |
| 2 | 2 | Name length | `name()` | ✅ |
| 4 | 4 | Data size, MSB = inline flag | `data_size()`, `data()` | ✅ |
| 8 | 4 | Data offset, or the data itself when inline | `data()` | ✅ |
| 12 | 4 | Data type | `data_type()` | ✅ |
| 16 | 2 | Flags | `name()` | ✅ |
| 18 | 2 | Spare | — | not read |
| 20 | n | Value name | `name()` | ✅ |

*"When the most significant bit is 1, data (4 bytes or less) is stored in the
Data offset field directly."* Implemented, and a size field with that bit set
and a length above four is treated as **corrupt** rather than read as either
shape — tested.

Value flags: `0x0001 VALUE_COMP_NAME` is used to pick the name encoding.
`0x0002 IsTombstone` (Windows 10 RS1+) is read as `KeyValue::is_tombstoned()`.
A tombstoned value still comes through the same `KeyValues` walk as every
other value — dropping it would lose real deleted-value evidence — but it
carries the flag so a caller can label it and keep it out of a "current data"
listing, rather than reporting a soft-deleted value as live.

All twelve data types (`REG_NONE` … `REG_QWORD`, codes 0–11) are named. An
unrecognised code is reported as `Unknown(code)` rather than folded into
`RegBinary`: an examiner is entitled to the difference between "binary" and
"a type this format does not define".

## Subkey lists

| Signature | Entry size | Contents | Status |
|---|--:|---|---|
| `lf` — fast leaf | 8 | key-node offset + 4-character name hint | ✅ |
| `lh` — hash leaf | 8 | key-node offset + name hash | ✅ |
| `li` — index leaf | 4 | key-node offset | ✅ |
| `ri` — index root | 4 | offset of another subkey list | ✅ |

The hints and hashes are **not** read. They exist to make a lookup fast; this
reader enumerates and compares real names, because trusting a hash to decide a
key's name is how a reader reports a key that is not there.

`ri` nesting is bounded at eight levels (`MAX_INDEX_DEPTH`). A real hive nests
one level; a crafted one can point a list at itself, and an unbounded walk
would hang an ingest pipeline rather than fail it. One unreadable sublist does
not cost the sublists beside it — a damaged hive yields the keys it still has —
and the loss is carried, not swallowed: `SubKeyNodes::unresolved_sublists()`
names each sublist that would not read and why, and `is_incomplete()` says
whether the enumeration is short of what the index declared.

A leaf list (`lf`, `lh`, `li`) is bounded against its declared count when the
key's `subkeys()` is called and then read in place, one entry per `next()`,
with no allocation; an `ri` is resolved to its offsets up front, because that
walk is where the depth bound is enforced and damaged sublists are recorded.
`listed_len()` answers the same number before, during and after the walk in
either case. Pinned by `tests/subkey_leaf_alloc.rs` (zero allocations
enumerating `SAM\Domains\Account\Users\Names` on plaso's `SAM`, a hash leaf)
and `leaf_and_root_enumerations_agree_offset_for_offset`.

## Big data (`db`)

| Offset | Size | Field | Status |
|--:|--:|---|---|
| 0 | 2 | Signature `db` | ✅ |
| 2 | 2 | Number of segments | ✅ |
| 4 | 4 | Offset of the segment list | ✅ |

Segment list entries are 4 bytes each; each segment cell holds at most **16344**
bytes; used for data larger than 16344 bytes when the minor version is above 3.

This reader takes the big-data path when the declared size exceeds 16344 **and**
the cell carries the `db` signature — so a version 1.3 hive, which stores a
large value in one large cell instead, is read correctly by the same code.
Segments are joined **in list order** and the result truncated to the declared
size; order is the whole of the correctness here, because segments joined out
of order produce a blob that still parses and means something else.

## Names

Both encodings are implemented: one byte per character (ISO-8859-1) when the
structure's compressed-name flag is set, UTF-16LE otherwise. Undecodable input
— an unpaired surrogate, an odd byte count — yields a replacement character
rather than losing the key, and `to_string_checked()` exists for a caller that
would rather know.

There is **no name lookup**. Windows compares names case-insensitively across
the whole Basic Multilingual Plane, and a lookup that folds less than that
misses keys, and the crate does not ship a 1,500-line fold
table for a path nothing calls. Callers enumerate and compare names themselves.

## Key security (`sk`)

Offsets are within the cell payload — i.e. after the 4-byte
size field, which is what `Hive::cell_data` returns.

| Offset | Size | Field | Read as | Status |
|--:|--:|---|---|---|
| 0 | 2 | Signature `sk` | checked | ✅ |
| 2 | 2 | Reserved | — | not read (reserved) |
| 4 | 4 | Flink — next cell on the ring | `flink()` | ✅ |
| 8 | 4 | Blink — previous cell on the ring | `blink()` | ✅ |
| 12 | 4 | Reference count | `reference_count()` | ✅ |
| 16 | 4 | Security-descriptor size | `descriptor_size()` | ✅ |
| 20 | n | Self-relative security descriptor | `descriptor()` — bytes only | ✅ |

Fixed size 20 bytes before the descriptor.

**The descriptor is handed over, not decoded.** Owner and group SIDs, the DACL,
the SACL and their ACEs are `seance_core::secdesc`'s subject, because the same
NT structure appears in NTFS `$Secure:$SDS` and two decoders for one format can
disagree with each other on a court-facing surface.

**The reference count is transcribed, never repaired.** In all twelve real hives
under `reference/plaso/test_data/` each cell's count equals the number of key
nodes pointing at it exactly — 289 descriptors accounting for all 117,488 keys
in `SOFTWARE`, 193 for 30,756 in `SYSTEM`, 2 for 65 in `SAM`. A count that
disagrees with a walk is therefore a fact about the hive, and a reader that
quietly corrected it would hide that fact from the examiner who needs it.

**A descriptor size larger than its cell is refused**, rather than served from
the bytes after the cell. Those bytes belong to some other structure, and
decoding them would produce ACEs that are not in the evidence.

**The ring is walked, and a ring that does not close says so.** Every `sk` cell
in a hive sits on one doubly-linked ring, which is how the distinct descriptor
population is enumerated without visiting every key: 289 reads rather than
117,488 on `SOFTWARE`. All twelve corpus hives close through `flink` and `blink`
with identical membership. A walk that revisits a cell without reaching its
start, or exceeds the cell ceiling, returns what it read with
`SecurityRing::is_incomplete()` set — never a silently short population.

## Layered keys (minor version 6)

Specification §"Layered keys", implemented in `src/layered.rs`.

| Rule in the specification | Read as | Status |
|---|---|---|
| Byte 13 of `nk`, counted from the most significant bit: bit 0 *Inherit class*, bits 6-7 *Layer semantics* — i.e. masks `0x80` and `0x03` | `LayeredKeyBits::from_raw`; spare bits kept in `raw` | ✅ |
| The byte only means this in a minor-6 hive | `KeyNode::layered_key_bits()` is `None` below minor 6 (the byte is spare there, and plaso's minor-3/5 hives hold stray values in it) | ✅ |
| A key's stack runs from the most derived layer towards the base; semantics 0 joins and continues | `LayeredKey` members, most derived first | ✅ |
| 1 `IsTombstone`: neither it nor anything below joins | a most-derived tombstone hides the key and is returned in `LayeredSubkeys::tombstoned`; one below a live node cuts the stack there | ✅ |
| 2 `IsSupersedeLocal`: joins, nothing below joins | stack stops | ✅ |
| 3 `IsSupersedeTree`: as 2, subkeys carry the same value | stack stops **and** lower layers' subkeys are hidden | ✅, interpretation (below) |
| Values: union over the stack, the lower ("child", more derived) node wins a name, tombstoned values excluded | `LayeredKey::values()`: `values`, `tombstoned`, `shadowed` | ✅ |
| Last-written time: the newest in the stack | `last_written_filetime()` | ✅ |
| Class: from the most derived node with *Inherit class* 0 | `class_name()` | ✅ |
| Stack bound: 126 "parent" nodes (build 15025+) | `MAX_LAYERS` = 127, a longer chain is refused | ✅ |

**What the specification leaves open, and what this reader decided.** The
specification cuts a superseding node's *own* stack; it does not say what
happens to subkeys that exist only in the layers below. This reader hides
them below `SupersedeTree` and below a tombstone, and merges them below
`SupersedeLocal` — the names' plain reading. The real chains contain both
supersede values but no case that tells the two readings apart for
subkeys, so this part is interpretation, not validation. Names are matched
across layers case-insensitively with Unicode simple uppercase, which can
differ from Windows' own upcase table on a few non-ASCII characters; every
name in the real chains is ASCII. A root key whose most derived node is a
tombstone is refused rather than presented as an empty registry.

**Graded on real evidence** (`src/tests/layered_corpus_tests.rs`, corpus at
`~/forensic_corpora/windows_container_layered_hives`, not redistributable):
two Windows Server 2022 Nano Server container chains from the public
Microsoft Container Registry — `dotnet/runtime:8.0-nanoserver-ltsc2022`
(base + 5 deltas) and `dotnet/sdk:8.0-nanoserver-ltsc2022` (base + 15
deltas, sharing the first six layers).

* **Published answer:** the merged `Session Manager\Environment` `PATH` is
  the value the images' Dockerfiles set with `setx /M PATH` — layer 3's in
  the runtime chain, layer 10's in the SDK chain, layer 3's again when the
  SDK chain is cut below layer 10, and the base's own `Path`
  (`REG_EXPAND_SZ`, returned as `shadowed`) with only layer 1 above it.
  This one is carried by the plain merge: it still passes with the layer
  bits ignored.
* **From the artifacts' own bytes:** the tombstoned key
  `WMI\Autologger\Diagtrack-Listener\{976A8310-…}` (layer 15) is absent from
  the merged view and reported — a tombstone over a key no lower layer
  holds, so it proves reporting, not hiding; hiding an existing key is
  pinned only on a synthetic fixture. The tombstoned value
  `Windows Containers\CryptoSpecializeNeeded` hides layer 1's `REG_DWORD`
  until a later layer writes it again. `Lsa\Data` (`SupersedeTree`) stacks
  only its delta node and takes its class name from it; the base node has
  none. These fail when the layer bits are ignored.
* **Cross-check, not an answer key:** whole-chain merged key and value
  counts (e.g. SDK-chain SYSTEM 8,139 keys, 19,916 values, no faults)
  equal an independent Python walk of the same reading of the
  specification.

## Not implemented, and not silently

* **Writing.** This is a read-only reader.
* **Transaction-log replay** (`.LOG1` / `.LOG2`, the dual-logging scheme, the
  Marvin32 hashes). `seance_plugin_registry` does that against the primary file
  this crate opens.
* **Recovery of deleted cells — through the live tree.** `cell_data` still
  refuses a free cell (`CellNotAllocated`), so no key or value iterator ever
  hands back unallocated bytes. Deleted cells are mined separately, and only
  separately: `Hive::unallocated_cells()` walks the free cells (at most
  `MAX_UNALLOCATED_CELLS`, 200,000, reported through `is_capped()` when hit)
  and returns each `nk`/`vk`-shaped one wrapped in a `RecoveredCell` (`Key`,
  `Value` or `Undecodable`), which `seance_plugin_registry::recovered`
  publishes. The plugin's own raw `nk` walker (`MAX_NK_CELLS`) still runs
  beside it; it has not been retired.
* **Finding a layer chain.** `LayeredHive` merges the hives it is handed, in
  the order it is handed them; it does not find a container's layers or
  work out their order. Nothing in the product does yet:
  `seance_plugin_registry` still reads a `*_Delta` hive on its own, as a list
  of one layer's changes (ROADMAP §5.9).
