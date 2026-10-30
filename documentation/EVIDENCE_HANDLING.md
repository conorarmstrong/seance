# Evidence handling

How Séance treats the evidence it is given.

What the tool does to the material you point it at, stated plainly because it
is the first thing a lab needs to know.

**Evidence files are opened read-only.** `FileDataSource` opens with
`File::open`, which requests no write access, and no ingestion path opens an
evidence file for writing. Container formats are read-only by construction
(E01/EWF, AFF4, APFS). This is a property of the code, not a substitute for a
hardware write blocker at acquisition time — Séance examines an image that has
already been acquired, and how it was acquired is outside its control.

**Acquisition hashes are recorded and re-verified.** The hash computed at
ingest and any later recomputation both reach the report's Evidence Integrity
section, which is what demonstrates the material did not alter in custody.

**Some parsers spill evidence-derived data to the system temporary
directory.** A PST mailbox of format version 14, 15 or 23 is one (a version 36
OST is read in memory): the library that reads it requires a seekable
file, so the store is written to `$TMPDIR` and removed when the parse finishes,
including on the error paths. Two consequences worth planning for — the spill
lands wherever `TMPDIR` points, which may be a less protected volume than the
case workspace, and a process killed mid-parse leaves the file behind. Point
`TMPDIR` at storage held to the same standard as the case data.

**Unlock secrets are never persisted.** A LUKS passphrase, BitLocker password or
iOS backup password passed on the command line is handed to the decryptor module
at registration and lives only in process memory. It is not written to artifact
metadata, the case database, or an export.
Keys *derived* from an iOS backup password an examiner types to unlock a backup
for reading are held in process memory for one case, with a time limit, and are
never written anywhere either; a restart forgets them. (The unlock, like ingest,
does write the backup's decrypted `Manifest.db` — file names, domains and wrapped
per-file keys, not the password or the class keys — to a temporary file while the
password is checked.)

**The workspace is a second copy of evidence-derived content.** The search index
stores each artifact's extracted text (up to 16 MiB per artifact), the case
database holds parsed record content, and decoded thumbnails are cached — none
of it encrypted. That is the right design for a workstation tool: encrypting a
working set beside its own key protects against little, and full-disk encryption
is what answers a stolen machine. But it means the workspace belongs on the same
media, under the same handling, and in the same disposal as the evidence.
[DEPLOYMENT.md](DEPLOYMENT.md) itemises what is in there.

**Deployment**: mount evidence read-only, as
[DEPLOYMENT.md](DEPLOYMENT.md) sets out, so that ingestion cannot
alter originals regardless of what the code does.
