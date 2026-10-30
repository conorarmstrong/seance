# LICENSING.md — Séance's own code is MIT, and two libraries it links are LGPL

Séance is **MIT licensed**: every crate in this workspace, the interface, the
scripts and the documentation. Nothing you write against it, and
nothing you build on it, takes on a copyleft obligation.

**Two footnotes, and they are on this page because "fully open source" is a
claim someone will check.** A default build links two LGPL-3.0-or-later C
libraries — `libewf` for EnCase/E01 images and `libesedb` for the ESE
databases (SRUM, WebCacheV01, the Windows Search index). Their obligations
attach to *those libraries*, not to your code; what they mean in practice is
below. A third and much larger problem, a
GPL-2.0-or-later registry-hive reader that made the whole binary GPL, is not
present: the project wrote its own.

`LICENSE` carries the MIT text.

## What is covered

| What | Licence |
|------|---------|
| Every crate in the workspace | **MIT** |
| The React web interface | **MIT** |
| The scripts and the documentation | **MIT** |
| A binary built with `--no-default-features` (or without `e01` and `esedb`) | **MIT** |
| A binary built with the **default** features | MIT, **plus LGPL-3.0-or-later for `libewf` and `libesedb`** |

The last two rows are what matters in practice, and they are different rows. A
permissively licensed *source* tree can still produce a binary whose
distribution carries another licence's terms, if something it links does.

`seance_api`'s default feature set is `["e01", "esedb", "heic",
"video-thumbs"]`. The first links `libewf` (through `pkg-config` and
`bindgen`, against the system library); the second links `libesedb` through
the `libesedb`/`libesedb-sys` crates, whose own manifests declare
`LGPL-3.0-or-later` and which build the vendored C. `heic` and
`video-thumbs` link `libheif` and `openh264`, which are LGPL and BSD-2-Clause
respectively — `libheif`'s own terms are LGPL-3.0-or-later as well.

**What that means, in plain terms.** The LGPL is *weak* copyleft: it puts
obligations on the library, not on the program that uses it. Your own code —
and Séance's — stays under its own licence. What it asks of someone who
**redistributes a binary** is that the LGPL parts stay identifiable and
replaceable: ship their licence text, say where their source is, and do not
prevent a user relinking the program against their own build of them. Using
Séance in casework, modifying it, and building it for yourself are not
distribution and raise none of this.

**And if you would rather not have them at all:** build with
`--no-default-features` and add back the features you want. E01 images and the
ESE databases are then unreadable and the product says so on the record rather
than silently skipping them, which is the trade that feature exists to make
explicit.

## Data the binary embeds

The OCR models in `seance_plugin_ocr/models/` are not MIT. Their model card states CC-BY-SA 4.0, so
a distributed binary keeps that attribution and share-alike for them. [NOTICE.md](NOTICE.md) has
the detail, the fonts and the test-corpus credits.

## How the dependency side stays true

`deny.toml` lists the licences a dependency may carry, and the list holds
permissive terms and the file-scoped weak copyleft (MPL-2.0, LGPL) whose
obligations attach to the dependency's own source rather than to the work that
links it. **Strong copyleft is not on it**, and that is what the gate is for:
it cannot and does not claim the graph is all-permissive, because it is not. `cargo deny check licenses` runs in
CI, so a GPL dependency arriving by way of an innocuous upgrade fails the build
rather than quietly changing what this product may be distributed under.

## The registry hive parser

The `nt-hive` crate (Colin Finck, GPL-2.0-or-later) would have made any binary
that linked it distributable only under the GPL. This project does not use it.
The registry, amcache, shimcache and shellbags plugins and `seance_hive_util`
read hives through **`seance_hive`** instead.

`seance_hive` is written for this project from Maxim
Suhanov's [*Windows registry file format
specification*](https://github.com/msuhanov/regf), which is CC BY 4.0 — a
document, not code, and one that carries no copyleft into what is written from
it. The implementation is checked against that document field by field in
[`seance_hive/docs/SPEC_CROSSCHECK.md`](seance_hive/docs/SPEC_CROSSCHECK.md),
and the offsets in it are asserted in `seance_hive/src/tests/spec_tests.rs` so
a drift fails a test rather than a case.

Two properties are worth knowing:

* It **exposes each key's last-write time and its subkey and value counts**.
  The registry plugin carries all three onto every key record, so a key
  inventory can distinguish a key written during an incident from one written
  at install.
* It **returns errors rather than asserting**. A buffer whose signature is not
  `regf` is an ordinary error, not a panic.

`vendor/` still carries `evtx`, which is MIT/Apache-2.0.

## The carving signatures

They cover the same formats PhotoRec does, and their documentation refers to
PhotoRec throughout — where PhotoRec walks a packet chain, what its size caps
are, where Séance deliberately does less. Those are comparisons with another
tool's published behaviour, and the magic byte sequences they discuss are facts
about the file formats, fixed by the specifications and owned by nobody. The
implementation is this project's own, written in Rust from the format
documentation rather than translated from PhotoRec's C.
