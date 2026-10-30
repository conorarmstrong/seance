# BITS queue fixtures (`qmgr0.dat`, `qmgr1.dat`)

Real bytes from the NIST CFReDS Data Leakage PC (Windows 7), MFT entries 15553
and 15554 under `/ProgramData/Microsoft/Network/Downloader/`. Each fixture is
the **first 8,192 bytes** of the 4,194,304-byte file, unedited; every byte past
the cut is zero on the image, which `make_fixtures.py` checks before it cuts.
`MANIFEST.json` carries the source and fixture SHA-256.

What they pin (`tests/real_queues.rs`):

- `qmgr1.dat` — the live queue holds one job, "Setup Installer"
  `{7B403240-D166-4C09-958A-23774DF1F57A}`, owner
  `S-1-5-21-2425377081-3129163575-2985601102-1000`, the .NET Framework 4 web
  setup download from `go.microsoft.com` (872,448 bytes, transferred), with two
  DPAPI "BITS job credentials" blobs reported present and not decrypted. Past
  the live structure, two Outlook offline-address-book transfers
  (`diff1867.tm_`, `diff1868.tm_` from `outlook.office365.com`) are carved and
  labelled as stale.
- `qmgr0.dat` — the live queue is empty; the .NET download and both OAB
  transfers survive only past the live structure, and are carved.

DFIR Madness case 001 DC01's queue (Server 2012 R2, empty) is not committed:
the case's terms do not grant redistribution. It is reached through
`SEANCE_DC01_QMGR`; the whole Data Leakage files through
`SEANCE_CFREDS_QMGR_DIR` (`documentation/TESTING.md`).
