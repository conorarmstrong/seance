# Public PST stores and their libpff listings

The stores are not in this repository. Each `<store>.libpff.tsv` is the output of
`scripts/oracle/pst_list.py` (pypff, libpff-python 20260926) over the store: `node id`, attachment count,
folder path, subject and the first 60 characters of the plain-text body, one row per message.

| store | version | source | licence | SHA-256 |
|---|---|---|---|---|
| `pstsdk-sample1.pst` | Unicode (23) | enrondata/pstsdk `sourceCode/fairport/trunk/test/sample1.pst` | Apache-2.0 | `9e77f0f7937768506f85eb33b7c114e23ddf3bc7fd5d85226fce56586a8e3618` |
| `pstsdk-sample2.pst` | ANSI (14) | same, `sample2.pst` | Apache-2.0 | `587a1ae2785eb218d7d42a98d43ded546aa72670908269d7b3ab25a711a91871` |
| `pstsdk-test_ansi.pst` | ANSI (14) | same, `test_ansi.pst` | Apache-2.0 | `f1ff591b7441f8fcf78cc6c65a78c5d168763338f2fcdf3df5745e742bd66d04` |
| `pstsdk-test_unicode.pst` | Unicode (23) | same, `test_unicode.pst` | Apache-2.0 | `3f2b8ebf011ca754b9c2017d264423e173ef1407f460bd4cefde4a6ccc041f8b` |
| `pstsdk-submessage.pst` | Unicode (23) | same, `submessage.pst` | Apache-2.0 | `b619c5c7746e119fbdc6056d0acd70dc3d900a6fba2875570283aec7c3ef73e1` |
| `tika-variousBodyTypes.pst` | Unicode (23) | apache/tika `testPST_variousBodyTypes.pst` | Apache-2.0 | `24c5e6bbb8bf26a817c977283e40e7b69d2661fec0845abbe177f97efcb05fb0` |

Obtained 2026-10-22 from the fixture corpus of `justanyone/pypstreader` (`tests/fixtures/public/`, commit as cloned that day), whose
`MANIFEST.sha256` the files were checked against (`sha256sum -c`: OK). They are held at
`~/forensic_corpora/public_pst/stores/`; name that directory with `SEANCE_PUBLIC_PST_CORPUS`.
`javalibpst-dist-list.pst` (java-libpst, Apache-2.0) is also held; libpff cannot read it, so it has no listing here.

## pst-extractor-contacts.pst and pst-extractor-contacts97-2002.pst

From the test data of [pst-extractor](https://github.com/HiraokaHyperTools/pst-extractor) (commit `238a905`, MIT licence),
as committed unmodified under `samples/pst-extractor/` of [bod09/pst-viewer](https://github.com/bod09/pst-viewer) and downloaded from
`https://raw.githubusercontent.com/bod09/pst-viewer/main/samples/pst-extractor/`. Test addresses only (`xmailserver.test`, `example.com`).
`contacts.pst` is the current (Unicode, version 23) format and `contacts97-2002.pst` the Outlook 97-2002 (ANSI, version 14) format of **the same
contact, whose name is Japanese**; the first is the answer for the second, because the text is UTF-16 in one and Shift-JIS bytes in the other.
Neither store names a code page; the message carries a locale (1041) and an Internet code page (50220).

| File | SHA-256 | Size |
| --- | --- | --- |
| `pst-extractor-contacts.pst` | `25f2d4c0b5b229487f9db5753b414ccbdd2481ff0d3b693a1192216f8be3b484` | 271,360 |
| `pst-extractor-contacts97-2002.pst` | `153df7e350d128e7fd03711a6f09865b058ccc56d8295ff4d8eeda6c459e2a94` | 271,360 |

## javalibpst-example-2013.ost

`src/test/resources/example-2013.ost` of [rjohnsondev/java-libpst](https://github.com/rjohnsondev/java-libpst) (Apache-2.0), an Outlook 2013 OST (version 36), 16,818,176 bytes,
SHA-256 `b18ff390d0c22273029ee580ab6025976af69a4f84e276d1b1c01a988650853d`. libpff reads it; `javalibpst-example-2013.recipients.tsv` is its recipient listing.

## enron-bailey-s.pst, enron-dean-c2.pst, enron-harris-s.pst

Three Unicode (version 23, permute-encrypted) mailboxes of the EDRM Enron v2 corpus as published in native PST by `intellekthq/enron-ferc-pst` on Hugging Face
(`zl_bailey-s_000.pst`, `zl_dean-c2_000.pst`, `zl_harris-s_000.pst`; licence CC BY 3.0 US, attribution "EnronData.org"; the publisher removed attachments and overwrote free space).
Held at `~/forensic_corpora/found_enron_edo_pst/hf/` and linked into `public_pst/stores/` under the names above; the file's own published SHA-256 list matches
(`SHA256SUMS`): bailey `b19062c8f0f448a63adf3443becc66816161d67f31ca264fe15494a13a139648` (26,428,416), dean `3c145c5d4e2b862f49fe46d03d38aa8d90770f8409a5496bf198c4197188cd1b` (46,744,576), harris
`16464d9be227bf78dc24b1bb48c5ed1f066c257f279a2acb57b4b9e5cbc89128` (15,508,480). The `.recipients.tsv` files list the messages with 82 or more (bailey) and 150 or more (dean, harris) recipients, from libpff through `scripts/oracle/pst_recipients.py`.
The stores are real people's mail (public record); no content beyond display names and addresses is quoted in the repository.

## *.cyclic.pst (synthetic)

`pstsdk-sample1.cyclic.pst`, `pstsdk-sample2.cyclic.pst` and `tika-variousBodyTypes.cyclic.pst` are the stores of the same name above re-encoded with the cyclic algorithm by `scripts/synth/pst_to_cyclic.py` (no Outlook wrote them). They are held with the public stores and are not in the repository; the same script makes `nromanoff_stark_research_labs.cyclic.pst` from the plaso store. `PST-CYCLIC-1` in `documentation/VALIDATION.md`.
