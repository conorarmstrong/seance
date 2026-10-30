# Outlook 2013 OST, format version 36 — real-file fixture

`iaman.informant_initialised_prefix.ost` is the first **3,360,768 bytes** of the
suspect's Outlook 2013 offline store on the NIST CFReDS Data Leakage case PC
image. It is a real file, not one written from documentation. Nothing in it was
edited: the cut is where NTFS says the written data stops.

## Where it came from

| | |
|---|---|
| Image | `cfreds_2015_data_leakage_pc.E01`–`E04` (NIST CFReDS, 2015; published SHA-1s verified 2026-09-19, see `~/forensic_corpora/cfreds_data_leakage/PROVENANCE.md`) |
| Partition | NTFS at sector 206,848 (`mmls`) |
| Path | `Users/informant/AppData/Local/Microsoft/Outlook/iaman.informant@nist.gov.ost` |
| MFT entry | 46112 (`ifind -o 206848 -n …` → 46112), sequence 18 |
| `$DATA` | size 16,818,176 bytes, **initialised size 3,360,768** (`istat`) |
| Extracted | 2026-09-26, `icat -o 206848 cfreds_2015_data_leakage_pc.E01 46112` (Sleuth Kit) |

Whole extracted file (16,818,176 bytes; every byte past 3,360,768 is zero):

- SHA-1 `e133182f58e9f1726f2166bf9fcd7d3f71b06ad9`
- SHA-256 `9c493e17becf7b346b0f63e52a1305cb410b9cd22d34fe1def2f49d849c05ad5`

This fixture, `head -c 3360768` of it:

- SHA-1 `33df52a3e41e3bbfebaaf841aa896efe0b49f351`
- SHA-256 `da8e14dd08abccbeef7ad180c8bdbe5edeb792ff5a443c39d0448d6be6151530`

## What it is

`!BDN`, client `SO`, `wVer` 36 — the 4 KiB-page layout Outlook 2013 and later
write, which the linked `outlook-pst` reader does not open. The header's
`ibFileEof` says 0x100A000 (16,818,176) bytes, so a reader handed only this
prefix must say that the file it was given is shorter than the one the header
describes. On the image the missing part reads as zeros; in the prefix it is
absent. Both are the same fact about the evidence — the data was never written
to disk — and neither may be walked as pages.

Measured facts the tests in `../../ost4k_real_test.rs` re-derive:

- NBT root: bid 0x36EB at 0x90000; BBT root: bid 0x36F0 at 0x91000.
- 351 node B-tree leaf entries, 381 block B-tree leaf entries; every page's CRC
  matches and no page or block lies past the initialised length.
- 123 of the 381 blocks are zlib-compressed (`cb` ≠ `cbInflated`).

## Known answers

From NIST's own answer key (`leakage-answers.pdf`, question 21, "List all
e-mails of the suspect"), not from this reader's output. The key's times are
local (UTC−4 in March 2015); the store holds UTC.

| Folder | Subject | From → To | Local time (key) |
|---|---|---|---|
| Inbox | Hello, Iaman | spy.conspirator → iaman.informant | 2015-03-23 13:29:27 |
| Sent Items | RE: Hello, Iaman | iaman.informant → spy.conspirator | 2015-03-23 14:44:31 |
| Inbox | Good job, buddy. | spy → iaman | 2015-03-23 15:14:58 |
| Inbox | RE: Good job, buddy. | spy → iaman | 2015-03-23 15:20:41 |
| Inbox | Important request | spy → iaman | 2015-03-23 15:26:22 |
| Sent Items | RE: Important request | iaman → spy | 2015-03-23 15:27:05 |
| Deleted Items | RE: It's me | spy → iaman | 2015-03-23 16:41:19 |
| Inbox | Last request | spy → iaman | 2015-03-24 09:25:57 |
| Deleted Items | RE: Last request | iaman → spy | 2015-03-24 09:35:10 |
| Deleted Items | RE: Watch out! | iaman → spy | 2015-03-24 15:34:02 |
| Deleted Items | Done | iaman → spy | 2015-03-24 17:05:09 |

The key's twelfth message, "It's me" (2015-03-23 16:38:47), is marked
"Recovered Item from unused area of OST file": it is not in the store's
B-trees. The deleted-mail walk (`ost4k::recover`) recovers it whole from stale node B-tree pages — node
0x2015E4 in Sent Items, data block at 0x61000, sent 2015-03-23 20:38:47 UTC —
graded in `../../ost4k_recover_real_test.rs`. The store also holds three Outlook "Synchronization Log" messages in
Sync Issues, which the key does not list.

## Licence

A U.S. Government work (NIST), treated as public domain (17 U.S.C. §105); the
case is published for tool testing. The mailbox is a scripted scenario, not a
real person's mail.
