# Seance REPL Design

**Interface:** Command-Line Interface (CLI) / TUI
**Status:** Active

The Seance REPL (Read-Eval-Print Loop) is a lightweight, keyboard-centric interface for interacting with the Seance API. It provides a streamlined command-line experience similar to modern CLI agents, replacing complex TUI menus with direct commands.

---

## 1. Layout & Interaction

The interface is divided into three sections:
1.  **Output Log (Top):** Displays command results, API responses, and system notifications. Scrolls automatically.
2.  **Command Input (Bottom):** Single-line input box for typing commands.
3.  **Status Bar (Footer):** Displays API URL, active Case ID, and connection status.

**Controls:**
*   **Typing:** Input goes to command box.
*   **Enter:** Execute command.
*   **Up/Down Arrows:** Cycle command history.
*   **Ctrl+C:** Exit.

---

## 2. Command Reference

All commands start with `/`.

### 2.1 General
*   `/help` - Show help message.
*   `/clear` - Clear output log.
*   `/quit` or `/exit` - Close REPL.
*   `/login <username> <password>` - Authenticate against the API server. The password is
    echoed as typed; on a shared or recorded terminal, log in through the web UI instead.
*   `/logout` - Discard the token from memory. The server session expires on its own schedule.

### 2.2 Case Management
*   `/case list` - List all available cases.
*   `/case create <name> [reference]` - Create a new case.
*   `/case switch <id>` - Set active case context.
*   `/case info` - Show details for active case.
*   `/case update <field> <value>` - Update case field (name/ref/examiner).
*   `/case delete` - Delete active case.

### 2.3 Evidence & Ingestion
*   `/ingest <path>` - Queue a new data source for ingestion into active case. The path is
    checked to exist locally before it is sent.

There is no `/ingest list`; the REPL would try to ingest a file named `list`. Data sources are listed with
`/artifact tree` and `/artifact recent`.

### 2.4 Analysis
*   `/search <query> [--regex] [--type <type>] [--ext <ext>]` - Perform full-text/regex search.
    A search that finds nothing prints `What was searched: <statement>`, the `universe`
    statement the API returns: "no hits" means absent only within that reach.
    Against a server that returns no `universe`, it prints that the server did not state what
    the search covers, so the empty result does not say the term is absent. A search with hits
    prints neither (`search_scope_lines`, pinned by `search_scope_tests`).
*   `/sweep <text> [--bytes <hex>] [--codepage <label>] [--ext <e,..>] [--region <r,..>]
    [--type <T,..>] [--path <prefix>] [--glob <glob>] [--max-hits <n>] [--max-bytes <n>]
    [--resume <artifact_id>:<offset>]` - The case-wide byte sweep (`ROADMAP` §1.2): `POST /cases/{id}/search/sweep` over the evidence bytes, not the index. The
    words that are not flags are one text pattern (UTF-8, UTF-16LE/BE and each `--codepage`);
    `--bytes` adds a hex pattern and, like `--codepage`, may repeat; `--ext`, `--region` and
    `--type` take comma lists. A flag with no value, an unknown flag, no pattern at all or a
    malformed `--resume` is refused locally with the flag named, never dropped. Every answer
    prints `complete: true|false` (the server's own), each ceiling reached with its number
    (`hit_cap_reached`, `byte_cap_reached`, `object_stream_cut`), the coverage and scope
    statements, offered/searched counts per region, the server's slack sentence verbatim,
    short reads, read failures and bytes past a declared size, and — when a ceiling cut the
    sweep — `next_cursor: continue with --resume <id>:<offset>`, a token that parses straight
    back. An endian-ambiguous hit prints both encodings and the other reading's offset. The
    first 50 hits are printed and the rest counted. Pure halves `sweep_request_body` /
    `format_sweep_response` in `seance_repl/src/sweep.rs`, pinned by its tests against
    fixtures in the route's shape (synthetic: they pin the printer, not the sweep).
*   `/timeline [limit]` - Show recent timeline events.
*   `/stats` - Show artifact statistics.
*   `/duplicates` - Exact (SHA-256) duplicate groups in the active case.
*   `/duplicates near [threshold]` - PDQ near-duplicate image groups, at most `threshold`
    bits apart (default 31). Presented as a lead for review, not an identification.
*   `/artifact <id>` / `/artifact children <id>` / `/artifact tree` / `/artifact recent` /
    `/artifact history <id>` / `/artifact delete <id>` - Inspect and manage artifacts.
*   `/hex <id> [offset] [len]` - Hex-dump artifact content.
*   `/memory layer <image_id> [--start <addr>] [--end <addr>]` - Save a memory image's decoded
    physical layer (ROADMAP §5.3, the `layerwriter` equivalent; `CORE_DESIGN.md` §4.4b).
    Addresses are decimal or `0x`-hex, `--end` exclusive; an unknown flag, a flag with no value
    or a value that is not a number is refused with the flag named. It fetches
    `GET …/memory/layer/{image}/manifest` first, prints the byte, fill and hole totals and the
    manifest's `statement`, and saves the response as `seance_layer_<image>[_<start>-<end>].manifest.json`
    in the working directory; then it streams `GET …/raw` chunk by chunk to
    `seance_layer_<image>[…].raw`. It prints `complete: …` only when every planned byte arrived,
    the transfer ended without an error and the raw response's `X-Layer-Manifest-Sha256` equals
    the saved manifest's `manifest_sha256`; otherwise `FRAGMENT — do not tender this file:` with
    each reason. The pure halves are `seance_repl/src/memory_layer.rs`, pinned by its tests.
*   `/browse [path]` - Browse the local filesystem.

### 2.5 Investigation & Reporting
*   `/bookmark` - Manage bookmarks.
*   `/module` - List and run analysis modules.
*   `/unlock <artifact_id> <kind> <secret>` - Supply a secret for one locked artifact in the
    active case: `POST /cases/{id}/artifacts/{artifact_id}/credential` with
    `{kind, secret}`. `kind` is `bitlocker_recovery_password`, `bitlocker_password`,
    `luks_passphrase`, `sevenz_password`, `signal_ios_key_spec`, `ios_backup_password`,
    `signal_backup_passphrase` or `whatsapp_key` (a `crypt14` WhatsApp backup's key
    file as hex, or its bare key as 64 hex digits; a `crypt15`'s 64-digit end-to-end key or
    its `encrypted_backup.key` as hex; ROADMAP §5.7) or `macos_keychain_password` (opens a macOS keychain's `DbBlob`; reveals no item) or `macos_system_key` (the 48 bytes of a Mac's `/var/db/SystemKey` as hex; opens `System.keychain` the same way) (the list is tested equal to the kinds the route
    takes); everything after the one whitespace character that ends the kind is
    the secret, taken verbatim — inner, leading and trailing spaces included, since a password
    may have them and a trimmed one is a different password — so a
    passphrase of several words is one secret; a secret that is only whitespace is refused
    with the usage text. Prints the module and job it started (`/module job <id>` to watch it): a wrong
    secret fails that job and changes nothing in the case. Like `/login`, the secret is echoed
    as typed — this full-screen UI has no masked input — and the history entry and scrollback
    line are rewritten to `/unlock <artifact_id> <kind> ********` immediately, whatever the
    outcome; on a shared or recorded terminal, use the web UI's Needs attention field.
*   `/unlock --read <artifact_id> <kind> <secret>` - Unlock for reading: `POST /cases/{id}/artifacts/{artifact_id}/unlock` with `{kind, secret}`.
    `kind` is `ios_backup_password`, `bitlocker_password`, `bitlocker_recovery_password` or
    `luks_passphrase`; the target is an encrypted backup's folder or file, or a locked
    BitLocker/LUKS volume, its decrypted volume or anything beneath it. The server holds the
    keys in memory for this case with a time limit; prints how long, and that the secret is
    not kept. The secret follows the same verbatim rule as `/unlock` and the line is rewritten
    to `/unlock --read <artifact_id> <kind> ********` immediately, whatever the outcome.
*   `/unlock --lock <artifact_id>` - Lock again: `DELETE …/unlock`; prints that the keys are
    forgotten (if any were held).
*   `/hashset` - Manage hash sets.
*   `/profile` - Manage examiner/analysis profiles.
*   `/filter` - Manage timeline/artifact filters.
*   `/audit` - View the case audit log.
*   `/verify <artifact_id>` - Verify an artifact's integrity against its recorded hashes.
*   `/status` - Show processing status: the process-wide outstanding-task count (`active_tasks`,
    `scope: "process"` — every case this server serves, not the open one) and, under `cases`,
    each case's own queued and in-flight work, with `unattributed_tasks` for work no case can
    yet claim. It is the JSON from `GET /api/v1/status` (`CORE_DESIGN.md` §4.8), printed as
    received; a server embedding that did not supply the census prints `cases: null` with a
    `cases_unavailable` reason rather than an empty map.
*   `/export timeline [json|csv|pdf|body]` / `/export bookmarks [json|csv]` /
    `/export report [pdf|html|xlsx|docx|rtf|xml]` / `/export audit [csv]` - Save an export to
    `seance_export_<kind>_<timestamp>.<ext>` in the working directory. The first format listed
    for each kind is the default when none is given. **A format the kind does not accept is
    refused**, with a message naming the accepted set and the default — it is never mapped to a
    neighbouring format (`seance_repl::export_url` and its test pin the
    table). A timeline CSV or JSON is
    a streamed export that ends with a verdict row; after saving one the REPL prints the file's
    own verdict, and names the file a **fragment** that must not be tendered when the row is
    missing. `/export timeline body` is the `mactime` body file
    (`GET /cases/{id}/timeline/export/body`): a **file** export — one row per `FileEntry` with
    its own MAC times, no timeline filter — saved as `.body`, whose verdict is its last `#` line
    and is read the same way. `/export report xlsx` saves the case report as a
    workbook (`GET /cases/{id}/export/xlsx`); `/export report docx|rtf|xml` save it
    as a Word document, RTF or XML (`GET /cases/{id}/export/{docx,rtf,xml}`, `CORE_DESIGN.md`
    §4.4a). The saved file's extension is derived from the response's `Content-Type`, not from
    the word typed: `.csv`, `.pdf`, `.html`, `.xlsx`, `.docx`, `.rtf`, `.xml`, `.body`
    (`text/plain`, the body file), else `.json` — the two OOXML types are matched before the
    bare `xml` they contain, so a DOCX is never saved as `.xml`.

---

## 3. Architecture

The REPL is a **"Dumb Client"**.
*   It does **not** access the database directly.
*   It performs all actions by making **HTTP requests** to the `seance` API server (default: `http://localhost:8080`).
*   It subscribes to the **SSE Event Stream** to display real-time notifications (ingestion progress) in the Output Log.

---

## 4. Implementation Status

- [x] **Core TUI:** Input loop, Output log, Status bar (Ratatui).
- [x] **API Client:** HTTP requests via `reqwest`.
- [x] **SSE Integration:** Real-time event streaming.
- [x] **Case Commands:** List, Create, Switch, Info, Update, Delete.
- [x] **Ingest Commands:** Ingest file.
- [x] **Analysis Commands:** Search, Timeline, Stats, Duplicates, Artifact, Hex, Browse.
- [x] **Session:** Login, Logout.
- [x] **Investigation & Reporting:** Bookmark, Module, Hashset, Profile, Filter, Audit, Verify, Status, Export.
