
## `envelope_index_v8_schema.sql`

Apple's own DDL, dumped with `sqlite3 ".schema"` from a real macOS 11
`Envelope Index` — Mail V8, database version 4.30006, framework 3654.60.0.2.21 —
found at `Users/eliflatt/Library/Mail/V8/MailData/Envelope Index` in the Magnet
Virtual Summit 2021 macOS CTF image.

**Why the schema and not the data.** That database's tables are empty: Mail was
opened on the machine and no account ever synced, so there is not one message
row anywhere in it. The schema is nonetheless the thing worth keeping, because
it is the part this project did not write — `documentation/TESTING.md`'s rule
about using at least one input this project did not author is exactly what this
satisfies for the reader's joins and column names. The rows the tests insert
into it are this project's, and every record the reader emits says so
(`basis: "schema_verified_rows_unverified"`).

One line of the dump is removed: `CREATE TABLE sqlite_sequence(name,seq)`.
That table is SQLite's own bookkeeping for `AUTOINCREMENT` columns, not part of
Apple's schema, and SQLite refuses to have it created by hand ("object name
reserved for internal use") — it recreates it itself from the `AUTOINCREMENT`
declarations that are still here. Nothing Apple wrote was dropped.
