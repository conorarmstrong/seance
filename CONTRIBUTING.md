# Contributing

## Build and test

```sh
cargo build --release -p seance_cli          # the CLI (libewf needed for E01)
cargo build --workspace                      # everything, including seance-ewf-helper
cargo test --workspace --all-features        # the Rust suite
cd frontend && npm ci && npx vitest run      # the web UI specs
scripts/ci-gate.sh                           # every gate CI enforces, locally
```

`cargo test` alone can pass while a gate fails; run `scripts/ci-gate.sh`
before opening a pull request. What each gate checks, and why some run on a
schedule rather than on every push, is in `documentation/CI.md`. The known-answer corpus is not in the repository;
`test_data/README.md` says what is expected where, and
`documentation/VALIDATION.md` how to run `seance-validate` against it. A
named-but-missing corpus is a skip, never a pass, and `SEANCE_REQUIRE_CORPUS=1`
turns the skip into a failure.

## Commits and pull requests

- Conventional commits: `type(scope): what changed and why` — `fix(search):`,
  `feat(ui):`, `docs(bugs):`. The subject says what the change does for the
  person affected, not what files it touched.
- One change per commit; a branch per piece of work; pull requests for review.
- **No attribution trailers.** No `Co-Authored-By:` lines, "Generated with"
  footers, or any mention of AI tooling in commit messages, PR descriptions,
  code comments, or documentation.

## Documentation is part of the change

Every document in this repository has an owner subject, listed in
`documentation/DOCUMENTATION_MAP.md`. When a change touches that subject
the document is edited in the same commit, not afterwards: the screens and
reports this tool produces are quoted under oath, and a document that describes
behaviour the code no longer has is a defect. In particular:

- A defect found and not fixed in the same change goes in `BUGS.md`.
- The online help (`frontend/src/pages/help/HelpPage.tsx`) is documentation
  that happens to be code; a shortcut or behaviour it describes changes only
  together with it.

## Forensic honesty

The output is relied on in court, so the code never presents more than it
knows. A parser that hits its ceiling says so in its record rather than
returning a shorter list that reads as complete; a page missing from a capture
is reported as unmapped, not as zeros; a tier that has never been validated
against real evidence carries that on every record it emits; an image that
cannot be decrypted is reported as ciphertext, never as content. When you add a
capability, add the disclosure of what it does not do in the same change, and
when a comparison or design document claims something, make sure the code will
assert it.

## Tests

Tests are named for the behaviour they pin, in words a reader can check against
the code — `the_macos_tier_is_registered_under_a_marker_that_says_it_is_unvalidated`,
not `test_macos`. A bug fix ships with the test that would have caught it.
Corpus-dependent tests declare the corpus they need and skip loudly without it.
A test that needs a short-reading, dribbling or in-memory `DataSource` uses
the shared doubles in `seance_core::test_support` (or `ByteSliceDataSource`),
never a private copy. `seance_tests/tests/no_private_io_doubles_test.rs` fails
the build on a struct under one of the retired names, and on any new struct
that holds only a `Vec<u8>` and implements `DataSource`, whatever it is called.
It does not catch every possible copy (a double with a second field, say), and
it names the older copies not yet retired in a list that may only shrink. See
`documentation/TESTING.md`.

## Reporting security issues

See `SECURITY.md`; do not open a public issue for a vulnerability.

## Vendored parsers

`vendor/` carries one upstream parser (`evtx`) with source patches that make
them fail closed on hostile evidence, wired in through `[patch.crates-io]` in the root
manifest and again in `fuzz/Cargo.toml`. Before bumping either dependency, read
`vendor/README.md`: each patch is marked `SEANCE PATCH` in the source and cites the register
entry that found the defect, and a bump that drops a patch reintroduces that defect.
