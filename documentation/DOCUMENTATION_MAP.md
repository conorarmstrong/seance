# The documentation map

Every document below has an owner subject. When a change touches that subject,
the document is part of the change, not a follow-up. When a new defect or
limitation is found, it is recorded in the same change, whether or not it
was fixed.

### Registers: these must never fall behind

| File | What it is | Update when |
|------|------------|-------------|
| `BUGS.md` | The **live** defect register: what is open or undecided, and nothing else. Short by design. | A defect or limitation is found and not closed in the same change; a decision is taken to leave one open. A defect that is closed or decided is removed. |
| `CHANGELOG.md` | Release notes, newest first, in the [Keep a Changelog](https://keepachangelog.com) form. | A release is tagged, or a change alters what a release contains. |
| `ROADMAP.md` | Where the product is going, what is blocked, and what evidence a blocked item needs. **Open work only**, in priority tiers and sprints, every item with a developer-day estimate. | Work lands that moves a roadmap item, or an item becomes blocked or unblocked. When an item ships it is **removed**, not struck through or narrated. When the remaining part shrinks, the estimate is re-made. |

An entry's **current** status is its **last** status line. Read to the end of an entry before reporting it.

### Product and design

| File | What it is | Update when |
|------|------------|-------------|
| `README.md` | What Séance is, what it does, how to build and run it. The first thing a stranger reads. | A capability ships, a command changes, or a build step changes. |
| `documentation/CORE_DESIGN.md` | Core architecture and the API specification. | An endpoint, schema or core contract changes. |
| `documentation/REPORTING_DESIGN.md` | How reports are shaped, and what each section may claim. | Report content or its wording changes — including what a section deliberately omits. |
| `documentation/{WINDOWS,LINUX,MACOS,ANDROID,IPHONE}_DESIGN.md` | Per-platform artefact coverage and how each is parsed. | A parser gains, loses or bounds coverage on that platform. |
| `documentation/FEATURES.md`, `documentation/EVIDENCE_HANDLING.md` | The full account of what Séance does and how it treats evidence. The README carries only a summary. | A capability ships, changes or is withdrawn; an evidence-handling rule changes. |
| `documentation/BUILD_AND_RUN.md`, `documentation/MODULE_DEVELOPMENT.md` | Prerequisites, build flags, run modes and the gates CI enforces; how to write a module. | A build step, flag or run mode changes; the module trait changes. |
| `documentation/Container_Formats.md` | Which container and image formats are supported, and to what depth. | Format support changes, including a refusal being added. |
| `documentation/MEMORY_BUILD_BINDING.md` | How build-variant struct members are resolved in the memory stack. | Symbol or build-binding behaviour changes. |
| `documentation/COMPARISON.md` | Honest comparison against commercial suites. **A capability claimed here must be one the code will assert.** | A capability lands, or a claim is found to overstate what the code does. |
| `documentation/DEPLOYMENT.md`, `documentation/PRODUCTION_READINESS_GAPS.md` | Running it for real, and what still stands between here and that. | Deployment steps change, or a readiness gap opens or closes. |
| `documentation/CI.md` | The CI gates and how to run them locally (`scripts/ci-gate.sh`). | A gate is added, removed or changed. |
| `documentation/REPL_DESIGN.md` | The REPL / CLI command surface: what each command does and how it talks to the API. | A REPL command is added, renamed, removed, or changes what it prints. |
| `SECURITY.md` | How to report a vulnerability, which versions are supported, and what is in scope. | The supported-version line, the reporting route, or the fuzz-target set changes. |
| `NOTICE.md` | Third-party credits: the LGPL libraries, the OCR models, the fonts and the test corpora. | A dependency with its own terms, a font, a model or a corpus is added or dropped. |
| `CONTRIBUTING.md` | How to build, gate and submit a change; the conventions a contributor is held to. | A build step, the CI gate script, or a convention in this file changes. |

### Frontend and the online help

| File | What it is | Update when |
|------|------------|-------------|
| `frontend/README.md` | Building and running the web UI. | Build, dev-server or tooling changes. |
| `frontend/CONVENTIONS.md` | The shared frontend patterns and primitives, so the next person reuses them instead of writing a fifth one. | A shared hook, primitive or convention is added or changed. |
| `frontend/src/pages/help/HelpPage.tsx` | **The online help is user-facing documentation that happens to be code.** It is quoted and relied on like any other document. | Any keyboard shortcut, surface, or documented behaviour changes. Read the handler before writing the claim — every statement here must be checkable against the code. |
| `frontend/src/pages/help/HELP_SYNC.md` | How the online help is kept in step with the product. | The help page's structure or its sync rules change. |

### Testing, data and validation

| File | What it is | Update when |
|------|------------|-------------|
| `documentation/TESTING.md` | The testing strategy, how big the suite is, and which tests are corpus-gated. | Test strategy changes, or a corpus gate is added or retired. |
| `documentation/UI_TESTING.md` | The browser-driven UI test layer: the harness in `scripts/ui-tests/`, the evidence and data-shape matrices, the per-screen interaction matrix, and the forensic-honesty assertions. | A screen, a viewer or a harness rule changes; a test dimension is implemented or a gap closed. |
| `documentation/VALIDATION.md` | Reproducible known-answer validation and how to re-run it. | A validation is added, or its procedure changes. |
| `documentation/METHOD_STATEMENTS.md` | **Generated, never hand-edited.** What each module reads, produces, **cannot** do and refuses — the paragraph an examiner reads aloud. Regenerate with `cargo run -p seance_api --bin method-statements`; the prose lives in `seance_api::method_statements` beside the code. | A module is added, renamed or retired, or a statement is written. A test fails when the file and the module set disagree, and a statement for a module the product no longer builds fails the build. |
| `seance_memory/tests/KNOWN_ANSWERS.md` | The known-answer set for memory forensics. | A known answer is added or corrected. |
| `test_data/README.md` | What is in the corpus and what each sample is for. | A sample is added, replaced or retired. |
| `seance_benchmarks/README.md` | How the benchmarks are run and read. | A benchmark is added or its method changes. |

### When a document and the code disagree

The code is what happens; the document is a claim about it. Fix the document, and
if the claim was load-bearing — a supported format, a recovered capability, a
keyboard shortcut an examiner relies on — record it as a defect too. A wrong
document that someone acted on is the same class of failure as a wrong screen.
