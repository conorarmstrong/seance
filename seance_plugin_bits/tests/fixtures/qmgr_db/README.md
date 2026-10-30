# BITS `qmgr.db` fixtures (Windows 10, ESE)

From the Lone Wolf scenario image (`LoneWolf.E01`, NTFS at sector 1259520),
directory `/ProgramData/Microsoft/Network/Downloader/`. Both unedited.

| Fixture | Source | Bytes | SHA-256 |
|---|---|---|---|
| `lonewolf_qmgr.db` | `qmgr.db`, MFT entry 92620, whole file (`icat -o 1259520 LoneWolf.E01 92620`) | 1,310,720 | `dbdab2b617a413f6b8951c934ca52f58e1e6898dc56fd8c8b6d60e851708d661` |
| `lonewolf_edb00001_log_job_blob.bin` | bytes `0x11066`–`0x11465` of `edb00001.log`, MFT entry 92614 (whole file SHA-256 `f07ffc9e628b4d4f6f6e07bfc2f4193b26bc1b88c4c4be119cf030cc0371dbe6`) | 1,024 | `07c605639b484210501fcd39a71003b3ec4eb1e3c2e48e1e0e137ef43864b27f` |

What they pin (`tests/real_queue_db.rs`):

- The database was imaged from a running machine. Its ESE header says dirty
  shutdown (state 2, page size 16,384), its `Jobs` and `Files` tables (columns
  `Id`, `Blob`) hold **no rows** as libesedb reads them, and the queue's recent
  state is in `edb.log` / `edb00001.log`, which are not replayed. The module
  must say so rather than report an empty queue.
- File records survive in database pages 32 and 42, which no table row points
  at; they are found by byte scan and labelled, never published as jobs.
- The log slice is a `Jobs` record image: a 16-byte GUID then the same job
  header `qmgr0.dat` carries — the job "UpdateBinary", owner
  `S-1-5-21-2734969515-1644526556-1039763013-1001`, normal priority, suspended.
