# Vendored parsers

Two upstream crates are carried here because they panic — or abort — on hostile
evidence and every parser in Séance must fail closed instead. Each directory is
a verbatim copy of the named crates.io release with the smallest source change
that closes the defect, every change marked `SEANCE PATCH` in the source and
listed below with the register entry that found it. The root manifest's
`[patch.crates-io]` points the workspace at these copies; `fuzz/Cargo.toml`
carries the same patch because the fuzz crate is its own workspace.

When an upstream release carries the fix, delete the `[patch.crates-io]` entry,
bump the dependency, and delete the directory.

## `evtx-0.8.5` (MIT / Apache-2.0)

| Patch | Where | Register |
|-------|-------|----------|
| A template's substitution count is refused when it exceeds the bytes left in the chunk; it was passed to `Vec::with_capacity` verbatim, and a hostile record aborted the process with a multi-gigabyte allocation. | `src/binxml/tokens.rs` | `HUNT-047` |
| `expected_number_of_characters * 2` widened before the multiply; the `u16` overflow panicked. | `src/utils/binxml_utils.rs` | `HUNT-037` (history) |
| String- and template-table chains stop at an entry already cached; a cycle went round for ever. | `src/string_cache.rs`, `src/template_cache.rs` | `HUNT-037` |
| `EvtxChunkData::validate_data_checksum` and `validate_header_checksum` answer `false` when the bytes their CRC covers are not all present; the slices were unchecked, and a truncated or carved chunk (`free_space_offset` past the end of the data) panicked with an index out of bounds. | `src/evtx_chunk.rs` | `HUNT-164` |

## Removed: `nt-hive-0.3.0`

Vendored here until 2026-09-13, when it was replaced by this project's own
`seance_hive`. It is GPL-2.0-or-later, and Séance is MIT: a binary linking it
was distributable only under the GPL, which made the product's own licence
statement need a footnote. `LICENSING.md` records the replacement and
`seance_hive/docs/SPEC_CROSSCHECK.md` checks the new reader against the
published format specification.
