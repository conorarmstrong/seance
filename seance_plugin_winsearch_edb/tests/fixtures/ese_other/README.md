# A non-index, non-queue ESE database (collision guard)

From the Digital Corpora 2018 Lone Wolf scenario image (`LoneWolf.E01`, NTFS at sector
1259520; https://downloads.digitalcorpora.org/corpora/scenarios/2018-lonewolf/). Unedited.

| Fixture | Source | Bytes | SHA-256 |
|---|---|---|---|
| `lonewolf_settingsync_meta.edb` | `Users/jcloudy/AppData/Local/Microsoft/Windows/SettingSync/remotemetastore/v1/meta.edb`, MFT entry 130219 (`icat -o 1259520 LoneWolf.E01 130219`) | 1,441,792 | `a2341594a70df454a35f70c932ece04b2b3211c16e831bd679a997b2b1cb67af` |

What it pins: every ESE database in a case reaches both `plugin.windows.search_index`
and `plugin.windows.bits`. This one is neither's, and each must publish nothing for it
under its own name (`tests/real_index.rs::committed_non_index_ese_databases_produce_nothing`,
`seance_plugin_bits/tests/real_queue_db.rs::a_committed_non_bits_ese_database_produces_nothing`)
— and a refusal, never an empty result, when it is named like the file the module reads
(`src/tests.rs` in both crates). It is a guard, not a known answer: it says nothing
about what either module reads from its own database.
