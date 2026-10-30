# Third-party notices

Séance's own code is MIT licensed. See [LICENSE](LICENSE) and [LICENSING.md](LICENSING.md).
This file credits the third-party material that the repository or a built binary carries.
The Rust and npm dependency licences are listed by `cargo deny list` and `frontend/package-lock.json`.

## Libraries a default build links under the LGPL

| Library | Licence | Where its source is |
|---------|---------|---------------------|
| `libewf` | LGPL-3.0-or-later | The libyal project, linked through the system library |
| `libesedb` | LGPL-3.0-or-later | The libyal project, built from the C source vendored in the `libesedb-sys` crate. The Rust wrapper is <https://github.com/sunsetkookaburra/rust-libesedb> |
| `libheif` | LGPL-3.0-or-later | The `libheif-sys` crate links it. Wrapper: <https://github.com/cykooz/libheif-sys> |

Anyone who redistributes a default binary must ship the LGPL text, keep these libraries
replaceable, and point recipients at the source above. `LICENSING.md` says how to build without
them.

`openh264` is BSD-2-Clause and is linked by the `video-thumbs` feature.

## OCR models

The two files in `seance_plugin_ocr/models/` are the models published by the `ocrs` project, embedded
in the binary. The Hugging Face model card states CC-BY-SA 4.0, and the training data is HierText,
which is also CC-BY-SA 4.0. Treat the models as CC-BY-SA 4.0. A distributed binary keeps the
attribution and the share-alike terms for them. The `ocrs` code is Apache-2.0 or MIT.
The models README explains what is and is not confirmed.

## Fonts

Both are SIL Open Font License 1.1. The web interface bundles them through the `@fontsource` packages, which carry the licence texts.

| Font | Copyright |
|------|-----------|
| Inter | 2016 The Inter Project Authors, <https://github.com/rsms/inter> |
| IBM Plex Mono | 2017 IBM Corp. |

## Test data

Fixtures and known-answer data come from public corpora. Each fixture directory has a README or
PROVENANCE file naming the source, the licence and the SHA-256 of each file.

| Source | Terms |
|--------|-------|
| Enron recipient lists in `seance_plugin_email/tests/fixtures/pst_public` | CC BY 3.0 US, credit EnronData.org |
| pstsdk, Apache Tika and java-libpst PST samples | Apache-2.0 |
| `outlook-pst`, `pst-extractor` and plaso test data | MIT or Apache-2.0, as stated in each PROVENANCE file |
| Digital Corpora NPS M57 scenario | The corpora's terms. Third-party software inside a disk image keeps its own copyright |
| NIST CFReDS images | NIST terms. Credit NIST |
| Magnet User Summit 2022 CTF iPhone 8 | Not redistributed. Place the files by hand to run the tests |
