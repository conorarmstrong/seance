# UDF variant fixtures

These are **self-made** images, built on 2026-09-27 by third-party UDF writers. They are
not real-world discs. They pin how the translation layers in `seance_plugin_udf`
(virtual, sparable and metadata partitions; 512- and 4096-byte sectors) behave on
volumes another writer produced. They are **not** validation on a real burned disc.

The payload is `lean_payload.sha256` (5 files, 3 directories plus the root). It is the
lab corpus payload with `docs/big.bin` replaced by 384,000 bytes of a repeating text
line, so the images compress to a size fit for the tree. The payload's hashes are the
answer key.

| fixture (gunzip to get the image) | writer | what it pins | second decoder |
|---|---|---|---|
| `lean_vat_cdr_udf150.img.gz` | NetBSD `makefs -t udf -o T=cdr,v=1.50` | Type 1 + `*UDF Virtual Partition`, UDF 1.50 trailer-form VAT (`*UDF Virtual Alloc Tbl`) | udfinfo cannot read this VAT's LV extension (numfiles=0); see below |
| `lean_vat_dvdr_udf201.img.gz` | `makefs T=dvdr,v=2.01` | Type 1 + virtual, UDF 2.00+ header-form VAT (file type 248) | udfinfo: 5 files, 4 dirs |
| `lean_sparable_dvdrw_udf201.img.gz` | `makefs -s 64m T=dvdrw,v=2.01` | `*UDF Sparable Partition`, packet 16, two sparing tables | udfinfo: 5 files, 4 dirs |
| `lean_metadata_bdre_udf250.img.gz` | `makefs -s 32m T=bdre,v=2.50` | Type 1 + `*UDF Metadata Partition` | udfinfo 5/4; 7-Zip 26.00 extracts `docs/big.bin` with the payload hash |
| `lean_metadata_disk_udf250_512.img.gz` | `makefs T=disk,v=2.50` | metadata partition on 512-byte sectors | udfinfo 5/4; 7-Zip hash matches |
| `lean_plain_disk_udf201_4k.img.gz` | `makefs -S 4096 -s 8m T=disk,v=2.01` | physical partition on 4096-byte sectors | udfinfo: blocksize 4096, 5/4 (7-Zip does not read 4096-byte UDF) |
| `mkudffs_vat_cdr_udf150_empty.img.gz` | udftools `mkudffs --media-type=cdr --udfrev=1.50 --new-file` | a second VAT writer; closed, empty | udfinfo: 0 files, 1 dir |

makefs is built from github.com/Randrianasulu/makefs_termux @ e2c4fa1c (NetBSD code, BSD
licence). mkudffs and udfinfo are udftools 2.3 (GPL-2; only its output is committed
here). makefs records the build time and random volume IDs in each image, so a rebuild
will not be byte-identical. The SHA-256 of each image as committed:

```
1380cd99471acd34c02ace0c01ccca5dce199ad3a09ae11cb21941e627fe1cac  lean_metadata_bdre_udf250.img
754fe6941454dd6d9dbc43b1639dc6f4051d1e81abd70b7c896ba19d1c89b6a8  lean_metadata_disk_udf250_512.img
67e922b2afdb63bf8b4577049959b43815beeb259425360fc9720f03a79542da  lean_plain_disk_udf201_4k.img
c2c97ac02f5fe3564552683b9bf4b485dbed75379d112b9b68c8f0eedb229d7d  lean_sparable_dvdrw_udf201.img
bda5575b04acafa2e0d027a72f0f7bfcf2710715602843dc1cc73828a0190a67  lean_vat_cdr_udf150.img
24eab01aa3a48df69e7941669e19b13f4723c1f71c4e5ac564cd197030683ce9  lean_vat_dvdr_udf201.img
cd980fbb19f2701fa9a2a8af57d95f0b6eb7c3bbf8c3d9d3bbf8fd56f9fb2cb0  mkudffs_vat_cdr_udf150_empty.img
```

The fuller corpus these came from, where the Linux 5.15 UDF driver is the oracle for
most images, is graded by `tests/udf_variants_corpus.rs` (`SEANCE_UDF_IMAGES`).

## Hybrid ISO 9660 / UDF fixture

`hybrid_iso9660_udf250.img.gz` is `lean_metadata_bdre_udf250.img` with an ISO 9660 half
written by hand (a short script, not a disc authoring tool) into its free sectors 16-24:
a Primary Volume Descriptor and terminator at 16-17, the UDF Volume Recognition Sequence
moved to 18-20 (`BEA01`, `NSR03`, `TEA01`), and path tables, a root directory and one
54-byte file, `ISO_ONLY.TXT`, that the UDF tree does not hold. **Spliced, not authored:**
no burned or mastered hybrid was used; the real one is `UDF-BRIDGE-1`. Independent
decoders: `xorriso -indev <img> -ls /` lists `ISO_ONLY.TXT` and extracts it byte-exact;
`7z l -tudf <img>` lists the UDF half's 5 files and 3 folders. SHA-256 of the image:
`3083b28b5d9b2a0f02d6c258646229b7b78a8f4dc61935c8c680f52fe49cc388`.
