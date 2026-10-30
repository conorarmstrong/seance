# Apple Mail `.emlx` fixtures

These files were written by Apple Mail, not by this project. They are used as they were fetched, byte for
byte, by `tests/emlx_real_test.rs`.

## Committed here: liquidinvestigations/hoover-testdata (MIT)

* Source: https://github.com/liquidinvestigations/hoover-testdata, branch `master`. The emlx files were
  added at commit 03d64c4b on 2016-06-21 and fetched on 2026-09-19.
* Licence: MIT, "Copyright (c) 2019 The Liquid Investigations Authors". The full text is in `LICENSE`
  beside this file, copied unchanged from the repository.
* Files:

  | Here | In the repository (under `data/`) | sha256 |
  |------|-----------------------------------|--------|
  | `1498.partial.emlx` | `lists.mbox/F2D0D67E-7B19-4C30-B2E9-B58FE4789D51/Data/1/Messages/1498.partial.emlx` | `1199ba0bab414a740428f604f08e4d2e1f8366a8bcc16478f82ab0e890d5de09` |
  | `1498.3.emlxpart` | `lists.mbox/F2D0D67E-7B19-4C30-B2E9-B58FE4789D51/Data/1/Messages/1498.3.emlxpart` | `6d13fbd59c91e21f26b0630e7b9fbdfccf904a3fd0dd010b22027225e0462cc2` |
  | `missing-part/1498.partial.emlx` | `emlx-4-missing-part/1498.partial.emlx` (the same bytes as the first file) | `1199ba0bab414a740428f604f08e4d2e1f8366a8bcc16478f82ab0e890d5de09` |

* Content: a real mailing-list message (`Return-Path: <date-deschise-bounces@lists.okfn.org>`) that Apple
  Mail stored partially downloaded. Part 3, an `application/pdf` attachment, is a stub in the message
  (`X-Apple-Content-Length: 76502`), and its base64 body is in `1498.3.emlxpart`. The `missing-part/` copy
  is the same message with no part file beside it. It pins the "part is absent" answer.

## Not committed: digital-preservation/PRONOM_Research (no licence)

`2.emlx` (1,066 B) and `9.emlx` (18,582 B), written by Apple Mail 13.4, come from
https://github.com/digital-preservation/PRONOM_Research, `Submissions/EMLX/Samples`. The repository
carries no licence, so these files are **not** redistributed here. The real-file test reads them through
the corpus gate from `$SEANCE_EMLX_CORPUS` (locally `~/forensic_corpora/emlx_samples`, given as an absolute
path), at `pronom_research/2.emlx` and `pronom_research/9.emlx`. With the variable unset it prints
`SKIPPED (no corpus)` and passes, so a passing run without it says nothing about those two files. With the
variable set and a file missing it fails, and `SEANCE_REQUIRE_CORPUS=1` turns the skip into a failure.
