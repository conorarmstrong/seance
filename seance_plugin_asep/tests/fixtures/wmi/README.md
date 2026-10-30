# WMI repository fixtures

Page-subset copies of real `OBJECTS.DATA` files and whole real page-mapping
files, cut by `make_fixtures.py`
and described page by page in `MANIFEST.json` (source image, source SHA-256,
page list, fixture SHA-256). Every byte inside a fixture page is exactly as
Windows wrote it; the only editing is the choice of which 8192-byte pages to
keep, so record offsets within a page, descriptor tables, checksums and heaps
are unaltered and the records on a page can be cross-checked against the
source file with `strings -t x` or a hex viewer.

| File | Source | Pages kept | What the tests read from them |
|------|--------|------------|-------------------------------|
| `lonewolf-win10-objects-pages.bin` | Digital Corpora *Lone Wolf* scenario, `LoneWolf.E01`, Windows 10, `\Windows\System32\wbem\Repository\OBJECTS.DATA` (23,986,176 bytes) | 0, 1, 112, 130, 140, 143, 148, 1316, 2645 | Page 143 holds the machine's only subscription triad (`SCM Event Log Filter`, `NTEventLogEventConsumer` `SCM Event Log Consumer`, their binding). Pages 1, 112, 130, 140, 148, 1316 and 2645 hold the class definitions the decoder reads its layouts from, including two different `ActiveScriptEventConsumer` definitions. |
| `cfreds-xp-objects-pages.bin` | NIST CFReDS *Hacking Case*, `4Dell_Latitude_CPi.E01`, Windows XP, `\WINDOWS\system32\wbem\Repository\FS\OBJECTS.DATA` (5,464,064 bytes) | 0, 9, 58, 254, 328, 357 | The MD5 hash form and CRC-32 record checksums. Page 58 holds the SCM triad; page 328 holds a second filter and binding (`Microsoft WMI Updating Consumer Scenario Control`) whose consumer class `MSFT_UCScenarioControl` is defined there but whose instance is on page 359, deliberately left out so the "consumer not found" path is exercised. |

Neither machine carries a `CommandLineEventConsumer` or `ActiveScriptEventConsumer`
instance. The Data Leakage repository (below) holds a real
`CommandLineEventConsumer` -- Windows 7's stock `BVTConsumer` -- and that path is
graded on it (`VALIDATION.md` `WMI-1`). No repository, memory image or pagefile
on the build host holds an `ActiveScriptEventConsumer` instance, so that class is
decoded only through the same class-definition-driven decoder validated on the
instances that do exist (`HUNT-195` stays open for it). `wmi_tests.rs` says so
at the tests that describe the script consumer from records assembled in memory.

The whole source files are not in the tree. `wmi_tests.rs` re-runs the scan
over them when `SEANCE_LONEWOLF_OBJECTS_DATA`, `SEANCE_CFREDS_OBJECTS_DATA` and
`SEANCE_DATALEAKAGE_OBJECTS_DATA` name extracted copies (The Sleuth Kit:
`icat -o 1259520 LoneWolf.E01 89187`, `icat -o 63 4Dell_Latitude_CPi.E01 5507`
and `icat -o 206848 cfreds_2015_data_leakage_pc.E01 58925`).

## The page mapping

| File | Source | What the tests read from it |
|------|--------|-----------------------------|
| `lonewolf-win10-MAPPING1.MAP` | Lone Wolf, `\Windows\System32\wbem\Repository\MAPPING1.MAP` (MFT 89212, 79,044 bytes), whole | The active mapping (sequence 25064): logical 0 is physical 2645; physical 42 is logical 44 and logical 45 is physical 45; page 2713 is free. |
| `dataleakage-win7-MAPPING{1,2,3}.MAP` | NIST CFReDS Data Leakage PC, `cfreds_2015_data_leakage_pc.E01`, Windows 7, sector 206848, MFT 58922-58924, whole | The three rotating copies (sequences 26717, 26546, 26631); the highest is chosen, and with its footer flipped the next-highest. The copies carry stale bytes past their last section. |
| `cfreds-xp-OBJECTS.MAP` | CFReDS Hacking Case, `\WINDOWS\system32\wbem\Repository\FS\OBJECTS.MAP` (MFT 11943, 2,692 bytes), whole | The XP form: one section of 4-byte entries (sequence 4557). |
| `lonewolf-win10-objects-sparse.bin` | Lone Wolf `OBJECTS.DATA` pages 42, 43, 45, 2713 | Put back at their physical page numbers by the test: `Win32_ComputerSystem`'s definition opens on page 42 and continues on page 45 (the next logical page), not on 43; page 2713 is unmapped and holds one descriptor. |

The tests also put `lonewolf-win10-objects-pages.bin`'s pages back at their
physical numbers (the page list in `MANIFEST.json`), so the SCM triad on page
143 is read through the real mapping. The corrupted-footer, truncated and
"page dropped from the mapping" cases are these real files with bytes changed
inside the test; they pin a mechanism and are not evidence of real damage.

The expected values come from `independent_mapping_decoder.py`, written from
the format references and not from the Rust code. Its output over the whole
extracted files (`icat` as above; `OBJECTS.DATA` SHA-256s in `MANIFEST.json`
and `VALIDATION.md` `WMI-1`), 2026-09-26:

```
$ lw/MAPPING1.MAP lw/OBJECTS.DATA
sequence 25064 physical 2928 logical 2774 free 154 footer 0xdcba
mapped + free == all physical pages: True
pages 2928 continuation 1450 unmapped 154
descriptor records 11460 (in unmapped pages 1951)
spanning 364 reassembled 364
class definitions 7049 (reassembled 282; physically-next reading 233)
stored CRC-32s on spanning records 0: match 0, physically-next 0
$ lw/MAPPING2.MAP lw/OBJECTS.DATA
sequence 25050 physical 2928 logical 2774 free 154 footer 0xdcba
mapped + free == all physical pages: True
pages 2928 continuation 1450 unmapped 154
descriptor records 11460 (in unmapped pages 1951)
spanning 364 reassembled 364
class definitions 7049 (reassembled 282; physically-next reading 233)
stored CRC-32s on spanning records 0: match 0, physically-next 0
$ lw/MAPPING3.MAP lw/OBJECTS.DATA
sequence 25052 physical 2928 logical 2774 free 154 footer 0xdcba
mapped + free == all physical pages: True
pages 2928 continuation 1450 unmapped 154
descriptor records 11460 (in unmapped pages 1951)
spanning 364 reassembled 364
class definitions 7049 (reassembled 282; physically-next reading 233)
stored CRC-32s on spanning records 0: match 0, physically-next 0
$ dl/MAPPING1.MAP dl/OBJECTS.DATA
sequence 26717 physical 1806 logical 1715 free 91 footer 0xdcba
mapped + free == all physical pages: True
pages 1806 continuation 884 unmapped 91
descriptor records 7449 (in unmapped pages 677)
spanning 180 reassembled 180
class definitions 5110 (reassembled 98; physically-next reading 87)
stored CRC-32s on spanning records 0: match 0, physically-next 0
$ dl/MAPPING2.MAP dl/OBJECTS.DATA
sequence 26546 physical 1806 logical 1715 free 91 footer 0xdcba
mapped + free == all physical pages: True
pages 1806 continuation 884 unmapped 91
descriptor records 7449 (in unmapped pages 677)
spanning 180 reassembled 180
class definitions 5110 (reassembled 98; physically-next reading 87)
stored CRC-32s on spanning records 0: match 0, physically-next 0
$ dl/MAPPING3.MAP dl/OBJECTS.DATA
sequence 26631 physical 1806 logical 1715 free 91 footer 0xdcba
mapped + free == all physical pages: True
pages 1806 continuation 884 unmapped 91
descriptor records 7449 (in unmapped pages 677)
spanning 180 reassembled 180
class definitions 5110 (reassembled 98; physically-next reading 87)
stored CRC-32s on spanning records 0: match 0, physically-next 0
$ xp/OBJECTS.MAP xp/OBJECTS.DATA xp
sequence 4557 physical 667 logical 621 free 46 footer 0xdcba
mapped + free == all physical pages: True
pages 667 continuation 156 unmapped 46
descriptor records 3894 (in unmapped pages 237)
spanning 84 reassembled 84
class definitions 2865 (reassembled 83; physically-next reading 51)
stored CRC-32s on spanning records 84: match 84, physically-next 25
```

The choice among the three rotating copies does not change these counts on
either machine (the Data Leakage copies differ in two logical pages), so the
"highest sequence number" rule is pinned by the parser tests, not graded by
an outcome. On XP the stored CRC-32 of every reassembled record matches, which
does not rest on the decoder agreeing with itself.

Re-run: `independent_mapping_decoder.py <mapping> <OBJECTS.DATA> [xp]`;
`make_fixtures.py <lonewolf Repository dir> <cfreds FS dir> <data leakage Repository dir>`
regenerates every fixture here byte for byte.

## The index (`WMI-4`)

`independent_index_decoder.py <repository directory>` reads a whole repository's `INDEX.BTR`, mapping and
`OBJECTS.DATA` and prints the data references the index tree names (walked from its root) and the
descriptor-listed records it does not. `index_answer_key.json` is its output for the three Flare Windows 7
repositories and the Perseverance repository (sources and SHA-256s: `documentation/VALIDATION.md` `WMI-4`), the
answer `wmi_index_tests.rs` grades Séance against when `SEANCE_FLARE_WMI_DIR` and
`SEANCE_PERSEVERANCE_OBJECTS_DATA` name the whole files, which are not in the tree. It was written from the format
document and the bytes; `dissect.cim` 3.13 (AGPL-3.0) graded its output and is not a source of any code here.
The `synthetic_*` tests in `wmi_index_tests.rs` build a tiny index in the test and are mechanism checks only.
