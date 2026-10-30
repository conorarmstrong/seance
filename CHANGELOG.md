# Changelog

Release notes for Séance, newest first, in the format of
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Open defects are in [BUGS.md](BUGS.md) and planned work is in [ROADMAP.md](ROADMAP.md).

## [Unreleased]

## [1.0.1]

Fixes found by the first hosted CI runs on the public repository. No product behaviour changes.

- **Build.** `seance_container_e01` builds against newer libewf headers and newer glibc.
- **Dependencies.** `wasmtime` is 48.0.8, which clears RUSTSEC-2026-0422 to 0424.
- **Tests.** Acquisition source paths compare after canonicalisation, so macOS passes. The
  non-UTF-8 filename test is skipped on macOS, where APFS refuses such names.
- **CI.** The plaso test stores are pinned to a commit. Coverage frees runner disk first.
  The workspace test step lists every failure.
- **Repository.** The website and the Magnet iOS fixtures are no longer tracked.
  [NOTICE.md](NOTICE.md) credits third-party material.

## [1.0.0-rc]

The first edition. It is a release candidate: the workspace, the web UI and the release
tag all carry `1.0.0-rc`, and `scripts/check-version.sh` asserts that they agree.

### What it contains

- **Core.** A zero-copy data-source layer, a `ForensicsModule` plug-in trait with
  content-based detection, and an orchestrator that spills to disk instead of growing
  without limit. 157 modules are built at startup with the default features, in 127
  workspace crates.
- **Evidence in.** E01/EWF, AFF4, virtual disks, sparse and optical images, RAID and LVM,
  and encrypted volumes. Every format the product refuses is stated in
  [Container_Formats.md](documentation/Container_Formats.md).
- **Recovery.** File carving with 361 signature files, bulk-extractor-style feature
  extraction, and password recovery for LUKS, BitLocker and ZIP.
- **Artifacts.** NTFS, FAT, ext4 and the Windows, Linux, macOS, Android and iOS parser
  sets, email and messaging, and pcap and pcapng.
- **Memory forensics.** Process, network, handle, credential and tamper analysis for
  Windows, Linux and macOS images, graded against real captures. See
  [VALIDATION.md](documentation/VALIDATION.md).
- **Analysis.** Ranked findings, a needs-attention list, CSAM triage against Project VIC
  and CAID, a pivot across the case, a unified timeline, a communications view, a map and a
  connections graph.
- **Reports.** HTML, PDF, DOCX, RTF, XML and XLSX, with PDF signing. Each section states
  what it cannot show. [METHOD_STATEMENTS.md](documentation/METHOD_STATEMENTS.md) is
  generated from the code and states what each module reads, produces and refuses.
- **Case database.** SQLite with artifact lineage, an audit log and full-text search.
- **Web UI and CLI.** A React interface with six skins in light and dark, an in-app help
  reference, and a REPL.

### Validation

Known-answer results against published images and real captures are in
[VALIDATION.md](documentation/VALIDATION.md). The local gate `scripts/ci-gate.sh` passes on
this tree. Hosted CI has not run on it.

### Known limits

The open defects are in [BUGS.md](BUGS.md). Work that is planned or waiting on evidence is
in [ROADMAP.md](ROADMAP.md).

[Unreleased]: https://github.com/conorarmstrong/seance/compare/v1.0.1...HEAD
[1.0.1]: https://github.com/conorarmstrong/seance/compare/v1.0.0-rc...v1.0.1
[1.0.0-rc]: https://github.com/conorarmstrong/seance/releases/tag/v1.0.0-rc
