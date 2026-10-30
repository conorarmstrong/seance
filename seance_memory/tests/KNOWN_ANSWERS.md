# Known answers for memory-forensics validation

Ground truth for the memory tier. These are the numbers Séance must reproduce.
They are not aspirational: a disagreement is a defect in Séance until proven
otherwise.

**Two kinds of answer live here, and they are not equally strong.** Most come
from Volatility 3 2.28.2 run against the same public reference image — a second
implementation, independently written, which is strong corroboration. Two do
not: the Windows 11 25H2 kernel identity is checked against **Microsoft's own
PDB**, and the Linux kallsyms case against **the captured host's own
`/proc/kallsyms` from the same boot**. Each section says which it is, because
"another tool agrees" and "the vendor's published answer" are different
evidential claims and a document that renders them alike has lost the
distinction that matters.

Reproduce a Volatility oracle with:

```
cd reference/volatility3
.venv/bin/python vol.py -q -r csv -f <image> <plugin>
```

Volatility prints kernel addresses with the sign-extension truncated
(`0xffffae80…` as `0xae80…`). Compare masked to 48 bits rather than "correcting"
either side into agreement.

## The images, and how each is reached

| Image | OS / build | Corpus variable | Answers below |
|---|---|---|---|
| `win-xp-laptop-2005-06-25.img` | Windows XP SP2, x86 non-PAE | `SEANCE_MEM_IMAGES` | ✅ |
| `Win11Dump.mem` | Windows 11 22000, x86-64 | `SEANCE_MEM_IMAGES` | ✅ |
| `linux-sample-1.bin` | Debian 7, `3.2.0-4-amd64`, x86-64 | `SEANCE_MEM_IMAGES` | ✅ |
| `memdump.mem` | Windows 10 19041, x86-64, **smeared** | `SEANCE_LONEWOLF` | ✅ |
| `memory-unlocked.raw` | Windows 11 25H2, build 26200, x86-64 | `SEANCE_WIN11_MEMORY` | ✅ |
| An AVML capture + `vmlinux.btf` + `kallsyms.txt.gz`, same boot | Ubuntu 6.8 | `SEANCE_LINUX_MEM` | ✅ |
| `tigger.vmem`, `be2.vmem`, `zeus.vmem` (Malware Analyst's Cookbook; **not redistributable**, live malware) | Windows XP SP2, x86 PAE | `SEANCE_COOKBOOK_MEM` | ✅ tamper checks |
| `stuxnet.vmem` (Ligh 2011; **not redistributable**, live malware) | Windows XP SP3, x86 PAE | `SEANCE_STUXNET_MEM` | ✅ tamper checks |
| `boomer-win2003-2006-03-17.img` (NIST CFReDS "Basic Memory Images", extracted from `memory-images.rar`) | Windows Server 2003 RTM (3790.srv03_rtm), x86 | `SEANCE_NIST_BASIC_MEM` | ✅ legacy timer table |
| `memdump.mem` (samsclass.info CNIT 121; **not redistributable**, clean lab VM) | Windows Server 2008 SP1 (6001), x86 PAE | `SEANCE_SAMSCLASS_2008_MEM` | ✅ declared-entry legacy timer table |
| MMUShell `aarch64/linux` and `aarch64/linux_debian` dumps (QEMU-emulated) | AArch64 Linux, 4 KiB granule | `SEANCE_MMUSHELL_AARCH64` | ✅ translation, and the `linux_debian` kernel root from its `VMCOREINFO` (`swapper_pg_dir - kimage_voffset` = `0x412ee000` = QEMU's `TTBR1_EL1` BADDR; `seance_plugin_memory_linux/tests/arm64_vmcoreinfo_real_test.rs`) — no profile |

`SEANCE_MEM_IMAGES` carries three images under one variable, and a *named*
corpus short a file **fails** rather than skipping — so all three must be
provisioned together or none can be used. Lone Wolf has its own variable
because it is public where the other two are not. See
`documentation/TESTING.md` for the gate's three behaviours.

## Image: `win-xp-laptop-2005-06-25.img`

Source: <https://downloads.volatilityfoundation.org/volatility3/images/win-xp-laptop-2005-06-25.img.gz>
(180,343,409 bytes gzipped; 536,715,264 bytes raw). Windows XP SP2, 32-bit,
**non-PAE** — this image exercises the two-level x86 page walk.

### `windows.info`

| Field | Value |
|---|---|
| Kernel base | `0x804d7000` |
| DTB | `0x39000` |
| Is64Bit | false |
| IsPAE | false |
| KdDebuggerDataBlock | `0x8054c060` |
| KdVersionBlock | `0x8054c038` |
| NTBuildLab | `2600.xpsp_sp2_gdr.050301-1519` |
| Major/Minor | 15.2600 |
| MachineType | 332 (IMAGE_FILE_MACHINE_I386) |
| KeNumberProcessors | 1 |
| SystemTime | 2005-06-25 16:58:47 UTC |
| NtSystemRoot | `C:\WINDOWS` |

### Row counts

| Plugin | Rows |
|---|---|
| `windows.pslist` | 47 |
| `windows.psscan` | 62 |
| `windows.pstree` | 47 |
| `windows.cmdline` | 47 |
| `windows.dlllist` | 1668 |
| `windows.handles` | 9456 |
| `windows.malfind` | 100 |
| `windows.modules` | 127 |
| `windows.svcscan` | 299 |
| `windows.netscan` | n/a — Vista+ only, fails on XP by design |

`psscan` exceeding `pslist` by 15 is the expected pool-scan signal: unlinked and
terminated `_EPROCESS` structures still resident in pool memory. Reproducing
*only* the 47 linked processes means pool scanning is not working, even though
`pslist` would look correct.

Counts here are **data rows**, not lines: `wc -l` on the CSV counts the header
and the trailing newline as well, which is one too many in each direction. Use
`tail -n +2 <file> | grep -c '[^[:space:]]'`.

### Spot values from `windows.pslist`

| PID | PPID | Name | Offset (V) | Threads | Handles |
|---|---|---|---|---|---|
| 4 | 0 | System | `0x823c87c0` | 61 | 1140 |
| 448 | 4 | smss.exe | `0x81fdf020` | 3 | 21 |
| 504 | 448 | csrss.exe | `0x81f5a3b8` | 12 | 596 |

### `windows.registry.hivelist` spot values

| Offset | Path |
|---|---|
| `0xe1ecd008` | `\Device\HarddiskVolume1\Documents and Settings\Sarah\Local Settings\Application Data\Microsoft\Windows\UsrClass.dat` |
| `0xe1eff758` | `\Device\HarddiskVolume1\Documents and Settings\Sarah\NTUSER.DAT` |

## Image: `Win11Dump.mem`

Source: <https://www.osforensics.com/downloads/Win11Dump.zip> (1,318,367,225 bytes
zipped). Windows 11 build 22000, **x86-64** — this image exercises the four-level
IA-32e page walk, 2 MB and 1 GB large pages, and canonical-address handling that
the XP image cannot reach.

### `windows.info`

| Field | Value |
|---|---|
| Kernel base | `0xf80029800000` |
| DTB | `0x1ae000` |
| Is64Bit | true |
| IsPAE | false |
| layer_name | `WindowsIntel32e` |
| KdVersionBlock | `0xf8002a409750` |
| Major/Minor | 15.22000 |
| MachineType | 34404 (IMAGE_FILE_MACHINE_AMD64) |
| KeNumberProcessors | 4 |
| SystemTime | 2022-07-18 23:26:00 UTC |
| NtSystemRoot | `C:\Windows` |

### Row counts

| Plugin | Rows |
|---|---|
| `windows.pslist` | 103 |
| `windows.psscan` | 103 |
| `windows.pstree` | 103 |
| `windows.cmdline` | 103 |
| `windows.dlllist` | 5950 |
| `windows.ldrmodules` | 5794 |
| `windows.handles` | 49665 |
| `windows.malfind` | 40 |
| `windows.modules` | 156 |
| `windows.netscan` | 101 |
| `windows.netstat` | 93 |
| `windows.privileges` | 3570 |
| `windows.getsids` | 1511 |
| `windows.registry.hivelist` | 38 |
| `windows.svcscan` | 1462 |
| `windows.vadinfo` | 17405 |

Unlike the XP image, `psscan` and `pslist` agree at 103 here — this capture has
no unlinked or terminated remnants. Use the XP image to prove pool scanning
finds what list walking cannot; use this one to prove the two agree when they
should, which is the other half of the same claim.

### Spot values from `windows.pslist`

| PID | PPID | Name | Offset (V) | Threads |
|---|---|---|---|---|
| 4 | 0 | System | `0xde8ce58c4040` | 152 |
| 124 | 4 | Registry | `0xde8ce592e080` | 4 |
| 376 | 4 | smss.exe | `0xde8ce78bc040` | 2 |

Matching symbols: `ntkrnlmp.pdb/8E3373D6124E747F0E72EF8E02E676B3-1.json.xz`.

## Symbols: `ntoskrnl.pdb/32962337F0F646388B39535CD8DD70E8-2.json.xz`

The matching ISF for the image above. 179,340 bytes xz-compressed.

| Property | Value |
|---|---|
| ISF format version | 6.1.0 |
| base_types | 13 |
| user_types | 558 |
| enums | 49 |
| symbols | 10390 |
| PDB GUID | `32962337F0F646388B39535CD8DD70E8` |
| PDB age | 2 |

### `_EPROCESS` member offsets (size 608)

| Member | Offset | Type |
|---|---|---|
| `Pcb` | 0 | struct `_KPROCESS` |
| `UniqueProcessId` | 132 | pointer to void |
| `ActiveProcessLinks` | 136 | struct `_LIST_ENTRY` |
| `InheritedFromUniqueProcessId` | 332 | pointer to void |
| `ImageFileName` | 372 | array[16] of unsigned char |

A symbol table that returns any other offset for these members is wrong, and
every process-listing result derived from it is wrong with it.

---

## Image: `memdump.mem` (Digital Corpora, Lone Wolf 2018)

Windows 10 build 19041, x86-64, 17 GB, taken with FTK Imager **on a running
machine**, so it is *smeared*: pages captured at different instants. Volatility's
own `windows.info` shows it — `KeNumberProcessors` reads 0 and the PE timestamp
reads 2042.

It earns its place beside the other two twice over. It is the only Windows 10
image here, and it is the only capture on which upstream's `windows.pslist`
returns **no processes at all** — so it is the case where "agrees with
Volatility" and "recovers the evidence" come apart, and the assertions have to
say which is meant.

Matching symbols: `ntkrnlmp.pdb/481F0DAABA6C4F02B456FAD74941C2A4-1`, in the
Volatility Windows symbol pack.

### `windows.info`

| Field | Value |
|---|---|
| DTB | `0x1ab000` |
| Is64Bit | true |
| Major/Minor | 10.0 |
| PDB | `ntkrnlmp.pdb` |
| PDB GUID | `481F0DAABA6C4F02B456FAD74941C2A4` |
| PDB age | 1 |

**Kernel base is deliberately not a known answer here.** The two tools disagree
about it on this image, and that disagreement has its own test rather than being
folded into a pass or quietly dropped: the list walk settles which base is
usable.

### `windows.psscan`

**216 allocations.** The expected value is the full *set* of `_EPROCESS`
addresses masked to 48 bits — generated from the oracle CSV, not typed — and it
is compared as a set, not a count. A count that matches while the addresses
differ is two errors cancelling, which on a smeared image is a live possibility.
A failure names what is missing and what is extra, because "a process was
missed" and "a process was invented" are not the same defect.

---

## Image: `linux-sample-1.bin`

Debian 7 running `3.2.0-4-amd64 #1 SMP Debian 3.2.57-3+deb7u2`, x86-64, 512 MiB
raw physical capture. Matching symbols:
`Debian_3.2.57-3+deb7u2_3.2.0-4-amd64_x64.json.xz`.

The oracle CSVs live in `~/forensic_images/memory/oracle_linux/`. Their row
counts are `wc -l` **minus two** — the CSV header and a trailing blank line.

### Row counts

| Plugin | Rows |
|---|---|
| `linux.pslist` | 133 |
| `linux.lsmod` | 79 |
| `linux.bash` | 27 |
| `linux.envars` | 1402 |

`linux.capabilities` has **no Volatility row count**, and that absence is the
point. Volatility's own `linux.capabilities` *fails* on this image, producing one
row and the error *"Volatility encountered an unexpected situation. No further
results will be produced."* — because Debian 3.2 names the type `kernel_cap_t`
where the extension is registered on `kernel_cap_struct`, and `cap_ambient`
(Linux 4.3+) does not exist on it. Séance's capabilities stage reuses the
`pslist` task walk and therefore reports **133** processes, complete. See
`documentation/MEMORY_BUILD_BINDING.md`, which opens on this defect class.

### Discovery facts

| Field | Value |
|---|---|
| Directory table base | `0x160_5000` |
| Kernel shift | `0xFFFF_FFFF_8000_0000` |
| Banner physical address | `0x140_0070` |
| Release | `3.2.0-4-amd64` |
| Pointer size | 8 |

### `task_struct` member offsets

| Member | Offset |
|---|---|
| `tasks` | 368 |
| `comm` | 920 |

---

## Image: `memory-unlocked.raw` (Windows 11 25H2)

Windows 11 build **26200**, x86-64, 10 GiB of guest RAM captured while the
machine's BitLocker volume was unlocked. Part of the corpus described in
`test_data/README.md`; also the image behind validation case **MEM-2**.

**This one's ground truth is Microsoft's, not Volatility's.** The ISF is
generated from Microsoft's own PDB for this exact kernel:

```
curl -o ntkrnlmp.pdb https://msdl.microsoft.com/download/symbols/\
  ntkrnlmp.pdb/E6426A07C26E66F8EB8594621A7B273B1/ntkrnlmp.pdb
python3 -m volatility3.framework.symbols.windows.pdbconv \
  -f ntkrnlmp.pdb -o E6426A07C26E66F8EB8594621A7B273B-1.json
```

### Discovery, from the bytes alone

Discovery here needs no symbols: the physical layout, the directory table base,
the kernel load address and the kernel's CodeView identity all have to be
recovered from the image before any analysis is possible.

| Field | Value | Established by |
|---|---|---|
| PDB GUID | `E6426A07C26E66F8EB8594621A7B273B` | Read out of the image's own CodeView record |
| Build | **26200** | `KUSER_SHARED_DATA` |
| DTB | non-zero, evidence no weaker than `Scanned` | The page-table proof, not a supplied value |
| Kernel base | in kernel space (`> 0xffff_0000_0000_0000`) | — |

**The build-lab string on this image says 26100 and is wrong.** The build number
is taken from `KUSER_SHARED_DATA` for exactly that reason. A tool that reports
26100 here has read the wrong field, not found a different machine.

The corpus also holds a crash dump and a hibernation file from the same machine,
and both must yield the **same** GUID: a reconstructed address space that
produces a different kernel identity has been reconstructed wrongly, and the
GUID is the cheapest thing that proves the page map works end to end.

### `tcpip.sys`: a known answer that says a stage cannot run

Provisioned (`900CF8F7561880DF85314A7B161495F8-1`, obtained the same way after
reading the driver's CodeView record out of the capture itself) — and the network
stage still cannot run. This is not a provisioning gap:

| Source | Symbols | Types |
|---|---|---|
| Microsoft's public `tcpip.pdb` | 10,376 | **0** |
| Volatility's bundled `tcpip.pdb` ISF | 9,329 | **0** |

Microsoft publishes `tcpip.pdb` as a *public* PDB — function and global names,
no structure layouts — for every build. Volatility works around this with
hand-authored netscan definitions per Windows version, and its newest
(`netscan-win10-20348-x64.json`) stops thousands of builds short of 26200. The
`_TCP_ENDPOINT` layout the stage needs is not published by anyone. Recorded here
so nobody repeats the attempt to find out.

### `svcdiff`: the sweep and the chain agree

Pinned by
`win11_corpus_analysis::the_services_list_is_recovered_by_walking_the_control_managers_list_head`
(`--release`):

| Enumeration | Services |
|---|---:|
| SCM chain walk (`Sc27` list head in `services.exe`) | **684** |
| Pool sweep for service records | **684** |
| Swept but not chained (`unlinked`) | **0** |

The lab VM ran nothing that unlinks a service, so the two agree exactly; the
test fails on any other answer.

### `unloadedmodules`: nine unloads, and a time field that is not a time

Pinned by
`win11_corpus_analysis::the_unloaded_driver_table_is_read_from_the_win11_capture`
(`--release`). **This build's ISF does not declare `_UNLOADED_DRIVERS`** — 46 of
the 1,724 `ntkrnlmp.pdb` ISFs on the build machine do, and this is not one of
them — so the read goes through the documented x64 fallback, at offsets no
fixture wrote. That is what makes these numbers worth recording: a wrong offset
here yields names that are not names, and no synthetic test would catch it.

| Field | Value |
|---|---|
| `MmLastUnloadedDriver` (a write **count**) | **9** |
| Slots read | **9** — `min(count, 50)`, and the table has not wrapped |
| Slots with a name | **9** |
| Record layout used | `documented_x64` |

The nine drivers, in slot order, are the ones Windows unloads during boot:
`hwpolicy.sys`, `WdBoot.sys`, `uiomap.sys`, `KMPDC.sys`, `dam.sys`,
`dump_dumpfve.sys`, `dump_storahci.sys`, `dump_storport.sys`,
`NetworkPrivacyPolicy.sys` — each with a page-aligned range in kernel space.

**`CurrentTime` on this build is an interval since boot, not a FILETIME.** The
nine values are `0x00e393cb`, `0x00f679a5`, `0x01432ad9`, `0x0152ff1d`,
`0x0152ff1d`, `0x029d0047`, `0x029d0047`, `0x029d0047`, `0x03728e86` — 1.491 s
to 5.784 s in 100-nanosecond units, rising with the unload order, which is what
a since-boot counter does and is nothing like a wall-clock time. Converted as a
FILETIME (which is what Volatility 3's `unloadedmodules` does, with
`wintime_to_datetime`) all nine date to 1601-01-01. Séance publishes them as
intervals and states that no absolute time is claimed. A later
change that starts emitting absolute times for these nine is caught by the test.

### `timers`: the clean-machine baseline, and a zero that is the point

Pinned by
`win11_corpus_analysis::the_timer_tables_are_walked_on_the_win11_capture`
(`--release`).

| Measurement | Value |
|---|---:|
| Processor tables walked | **8** (and `KeNumberProcessors` also reads 8) |
| Buckets walked | **4,096** — 8 × 512 |
| Declared bucket dimensions | `[2][256]` |
| Timers read | **209** |
| Timers carrying a DPC routine | **52** |
| Timers whose `Dpc` field decodes to null (no DPC) | **157** |
| Same timer, routine and period as Volatility 3 `windows.timers` | **52 of 52** |
| Routines landing in **no loaded module** | **0** |

This build stores `_KTIMER.Dpc` encoded with `KiWaitNever`/`KiWaitAlways` and
the timer's address. Decoded and checked against `_KDPC.Type`, 52 carry a DPC
and 157 decode to exactly 0 — the encoding of null. The zero below stands on 52
routines read.

The last row is the one a detection rule would be built on, and on a clean
machine it is zero. That is what makes the signal worth reporting at all.

The bucket count is 512 rather than 256: `_KTIMER_TABLE.TimerEntries` is declared `[2][256]` here and
`[256]` on all 1,233 older ISFs in the pack, so the count must be the product of
the declared dimensions. A reader taking the outer dimension would walk 2 of 512
buckets, find real timers in both, and look correct.

No due time is recorded for any of them, deliberately: `_KTIMER.DueTime`'s
encoding on modern x64 is not established by any source in this tree, and
`KiWaitNever`/`KiWaitAlways` — the globals an obfuscation of that field uses —
are declared on this build. The bucket's own `_KTIMER_TABLE_ENTRY.Time` is
published as the raw number it holds, with no epoch claimed.

### The three thread groups: three zeros, each a different statement

Pinned by
`win11_corpus_analysis::the_thread_groups_are_measured_on_the_win11_capture`
(`--release`). One pass over the threads feeds `suspended_threads`,
`debugregisters` and `orphan_kernel_threads`.

| Measurement | Value |
|---|---:|
| Threads examined | **1,514** over **129** processes |
| Suspend counts **read** | **1,514** |
| Threads with a non-zero suspend count | **0** |
| Threads whose own flags claim live debug registers | **0** |
| Debug-register rows | **0** |
| Orphan kernel-thread candidates | **0** |
| Graded orphan findings | **0** |
| User threads set aside before becoming rows | **1,284** |

The suspend zero is a statement about the machine **because** all 1,514 counts
were read; a zero with nothing read would be a statement about the build, and
the record carries both numbers so the two cannot be confused.

**Why the debug-register check reads only flagged threads.** Reading `_KTRAP_FRAME`'s `Dr0`–`Dr3`/`Dr6`/`Dr7` from every
thread with a non-null `TrapFrame` produces **nine rows on this clean capture,
five of them claiming armed breakpoints**. Every one is wrong, and the build's
own symbols say why: on 26200 `_KTRAP_FRAME.Dr0` shares offset 216 with
`ShadowStackFrame` and `Dr1` shares 224 with `Spare[5]`. The ISF flattens a
union, and the only thing that says which interpretation applies is the thread's
own `_DISPATCHER_HEADER.DebugActive` / `ActiveDR7` — which is **clear on all
nine**. The five "breakpoints" are shadow-stack pointers. The check reads
the registers only from a thread whose flags claim them, and this capture
produces nothing.

**And 1,284 of the 1,514 threads are user threads**, whose `StartAddress` is
`RtlUserThreadStart` in ntdll — a *user*-space module. The map orphan candidates
are attributed against is a map of *kernel* modules, so it cannot attribute that
address by construction and every user thread would look like an orphan. They
are counted, not published as observations; the remaining kernel threads all
start inside a loaded module, which is why there is no candidate at all.

### `etwpatch`: the modal prologues of this build

Pinned by
`win11_corpus_analysis::the_etw_write_path_is_examined_on_the_win11_capture`
(`--release`). The check reads the four ETW write exports out of **each
process's own** `ntdll` and runs two routes over them: classification of the
prologue, and comparison against the modal prologue across every corroborated
copy in the image.

| Measurement | Value |
|---|---:|
| Processes assessed | **123** |
| Export prologues read | **491** |
| Signals on either route | **0** |
| Processes unassessed | **6** |

The six are `System`, `Registry` and `MemCompression` — which genuinely map no
`ntdll` — and three whose loader list could not be reached. They are listed with
their reasons and **never reported as unpatched**.

**The modal prologue of each export on build 26200**, which is the part worth
recording because it is the build's own bytes:

| Export | First sixteen bytes | Agreed |
|---|---|---:|
| `EtwEventWrite` | `40 55 57 41 54 41 56 41 57 48 8d 6c 24 80 48 81` | 123 of 123 |
| `EtwEventWriteFull` | `4c 8b dc 48 83 ec 58 48 8b 84 24 90 00 00 00 49` | 123 of 123 |
| `EtwEventWriteEx` | `4c 8b dc 48 83 ec 58 48 8b 84 24 98 00 00 00 45` | 122 of 122 |
| `EtwEventWriteTransfer` | `40 55 57 41 54 41 55 41 57 48 8d ac 24 70 ff ff` | 123 of 123 |

**Why the classifier stops short of the window's end.** Look at `EtwEventWrite`'s
last two bytes: `48 81` is the start of a `sub rsp,imm32` that the sixteenth byte
cuts in half. A fixed-length window almost always ends mid-instruction, and
calling that an invalid instruction would classify genuine prologues as
undecodable. The classifier stops when fewer bytes remain than an instruction
can be (15 on x86-64), and all 491 classify as ordinary. The bytes above are pinned in the
test for that reason, not only the counts.

### `skeleton_key_check`: one `lsass`, one prologue, and a route that never runs

Pinned by
`win11_corpus_analysis::the_skeleton_key_check_examines_lsass_on_the_win11_capture`
(`--release`).

| Measurement | Value |
|---|---|
| `lsass.exe` in the process list | **1** (pid 968) |
| Examined | **1** |
| Signals | **0** |
| `cryptdll.dll` base in that process | `0x00007ffcd9940000`, corroborated as an image mapping |
| `CDLocateCSystem` | `0x00007ffcd9943150` |
| Its prologue | `8b 05 aa b9 00 00 4c 8d 15 83 c0 00 00 44 8b c9` |

Those bytes are the known answer: `mov eax,[rip+…]; lea r10,[rip+…]; mov
r9d,ecx`, an ordinary prologue. A wrong export address or the wrong module would
not produce them, which is why they are asserted rather than only the count.

**And the record is still marked incomplete**, on this capture and on every
other. The check has two routes and only one runs: the `CSystems` descriptor
table — an RC4-HMAC descriptor whose function pointer leaves `cryptdll`, which
is the stronger signal — needs the layout of that descriptor, and **nobody
publishes it**. Microsoft ships `cryptdll.pdb` as a *public* PDB: names, no
structure layouts, exactly as it ships `tcpip.pdb` (recorded above at 10,376
symbols and zero types). An ISF built from it would give the address of the
`CSystems` global and nothing about the entry layout. So the route is named
permanently as not run, with what it would have established — not as an item
pending a symbol file, which would be a promise this project cannot keep.

### `pebmasquerade`: a clean machine raises nothing

Pinned by
`win11_corpus_analysis::the_peb_masquerade_checks_are_measured_on_the_win11_capture`
(`--release`). The checks live in the `tampering` stage, which compares what a
process says about itself against what the kernel says about it.

| Measurement | Value |
|---|---:|
| Processes examined | **123** |
| Kernel audit paths read (`SeAuditProcessCreationInfo.ImageFileName`) | **123** |
| Audit-path disagreements | **0** |
| `ImagePathName` length-invariant breaches | **0** |
| Tampering signals of **any** kind | **0** |

**The last row is the one that matters.** An `image_vad_path_differs` signal
says "the range backing this process's image maps a file other than the one the
process claims to be". On a stock Windows 11 install a name cut off by
`_EPROCESS.ImageFileName`'s own terminator must not raise it:
`fontdrvhost.ex`, `RuntimeBroker.`, `msedgewebview2`, `StartMenuExper`,
`ShellExperienc`, `MicrosoftEdgeU`, `smartscreen.ex`, `CrossDeviceRes`,
`AggregatorHost`. The array is fifteen bytes, Windows 11 26200 stores fourteen
characters and a NUL in it, and the truncation test is `len + 1 >= width`.
Every process with a name over fourteen characters is therefore treated as
truncated, and the whole stage is silent on this capture.

The second number is worth keeping too. The loader allocates
`ImagePathName`'s buffer to fit the path and its terminator, so
`MaximumLength == Length + 2`; that holds for all 123 processes here, which is
what makes a breach of it worth reporting as a marker of a string edited in
place.

### `joblinks`: exact parity with upstream, once the row shapes are reconciled

Pinned by
`win11_corpus_analysis::job_objects_are_surveyed_on_the_win11_capture`
(`--release`). Volatility 3.2.28.2 prints **56 rows on this image: 24 job rows
plus 32 member rows**.

| Measurement | Value |
|---|---:|
| Processes walked | **129** |
| Processes in a job | **24** — upstream's 24 job rows |
| Processes in no job | **105** |
| **Distinct** job objects | **21** |
| Member rows under upstream's shape | **32** — upstream's 32 |
| Member lists that ended abnormally | **0** |

**The row counts differ and the sets do not.** Upstream iterates processes: a
job holding three processes is printed three times, with its members repeated
under each. This stage emits one record per distinct `_EJOB`, naming every
process that pointed at it — two rows for one kernel object would be two answers
to one question. Reconciling the two shapes is arithmetic on this record: 19
jobs named by one process each, one by two and one by three gives upstream's 24
job rows, and `Σ named_by × members` gives its 32. Both come out exactly.

**And one job's counter disagrees with its list**, on a clean machine: it
reports `ActiveProcesses = 7` and its `ProcessListHead` walk holds 3, with the
walk ending normally at its head. That is either a job mid-teardown or one whose
members have been unlinked, and both numbers are on the record — upstream prints
`0` for a member row's counters and never compares them. Recorded here because a
reader who sees only one of the two numbers cannot tell that they differ.

### `devicetree`: 245 devices where upstream prints 100, and the four that agree

Pinned by
`win11_corpus_analysis::the_device_tree_is_walked_on_the_win11_capture`
(`--release`), against Volatility 3.2.28.2 run on the same image.

| | Séance | Volatility |
|---|---:|---:|
| Drivers (DRV) | **124** | 129 (126 distinct names) |
| Devices (DEV) | **245** | 100 (98 distinct `(driver, device)` pairs) |
| Attachments (ATT) | **113** | 26 |

The 245 device rows are **245 distinct addresses** — each driver's chain carries
its own visited set, so nothing is double-counted. The 113 attachments are over
76 distinct attached devices, because a device that is itself in a driver's
chain has its own stack walked as well.

**Where upstream reports, the two agree.** Four `(driver, device)` pairs taken
from its own output are asserted in this record: `\Driver\ACPI` → `00000029`,
`\Driver\ACPI_HAL` → `0000000f`, `\Driver\PnpManager` → `0000000e`,
`\Driver\Wdf01000` → `KMDF0`.

**What differs is how much of each chain is walked.** Upstream's output holds at
most one device per driver; this record holds `\Driver\ACPI`'s 32,
`\Driver\PnpManager`'s 15, `\FileSystem\FltMgr`'s 14, `\Driver\pci`'s 9,
and so on — with the sequential PnP names an ACPI enumeration produces
(`00000029`, `00000028`, `00000027`, …), which is what Windows' own device
naming looks like. The attachments that follow from them are likewise ordinary
and are the ones an examiner wants: `Serial0` attached by `\Driver\Serial`
above ACPI's `00000028`, and an unnamed `\Driver\Serenum` device above *that* —
a textbook serial-port stack, two levels deep.

**Why upstream stops after one device per driver is not established here**, and
this record makes no claim about it. What is recorded is what each tool printed
for the same bytes, and that the devices this one reports beyond
the first are named the way real ones are.

### `vadyarascan` and `yarascan`: eight addresses, and what a host name looks like in RAM

Pinned by
`win11_corpus_analysis::yara_rules_find_the_known_marker_in_one_process_own_memory`
and
`win11_corpus_analysis::the_marker_is_found_in_the_one_process_that_holds_it_and_the_kernel_space_is_searched`
(both `--release`), against Volatility 3.2.28.2 run on the same image.

**The oracle.** `windows.vadyarascan --pid 4708 --yara-string FORENSIC-W11`
prints **8** matches in `taskhostw.exe`:

```
0x2ca2f84c44e  0x2ca2f84d9ed  0x2ca2f8508cb  0x2ca2f8511ba
0x2ca2f991c4b  0x2ca2f991d0d  0x2ca2f99206c  0x2ca2f992093
```

With the same string compiled as a rule, the `pattern_scan` stage reports
**exactly those eight addresses**, and the test compares them as a **set** and
not as a count: two scans can agree on eight and disagree about where, and a
disagreement about where means the planning or the attribution is wrong. A
count-only comparison passes on that.

*(Read one line of Volatility's CSV output per match, not one row: the `Value`
column wraps, so `wc -l` gives 16 for these 8. Counted with a CSV parser.)*

| `taskhostw.exe` (pid 4708) | |
|---|---:|
| Allocations in the VAD tree | 171 |
| Mapped regions planned and scanned | 1,126 |
| Bytes examined | 17,248,256 |
| Bytes mapped and unreadable | **0** |
| Matches | 8 |

All eight are in **two private `PAGE_READWRITE` allocations with no file behind
them** — `0x2ca2f840000`–`0x2ca2f93ffff` and `0x2ca2f990000`–`0x2ca2f99ffff` —
which is what a string written into a process's own heap looks like. The
protection is named from this kernel's own `MmProtectToValue`.

**The whole machine, which is the answer to a different question.**
`FORENSIC-W11` is this machine's **host name**, so it is in most processes on
it. Scanning every process with the same rule:

| The machine | |
|---|---:|
| Processes on the active list | 129 |
| Processes searched | 129 |
| Processes holding the string at all | 116 |
| Matches in process memory | 1,482 |
| Most in one process | 540 (`svchost.exe`, pid 3296) |
| Mapped process bytes examined | 3,361,988,608 |
| Mapped process bytes that would not read | **0** |

`taskhostw.exe` still reports its eight, at the same eight addresses, in a run
that searched the other 128 processes as well. That is the assertion that would
catch one address space being read through another's page tables, which a
per-process count taken in isolation cannot.

**The kernel's own space** — upstream's `yarascan` rather than its
`vadyarascan` — is swept in the same run:

| The kernel's address space | |
|---|---:|
| Mapped regions enumerated | 8,084 |
| Bytes examined | 2,212,950,016 |
| Bytes mapped and unreadable | **0** |
| Matches | 105 |

Those 105 carry **no allocation**, and say why: a virtual address descriptor
describes a process's user memory, so there is none to name in the kernel's
space. The whole run — 129 processes and the kernel — took **104 seconds** and
examined 5,574,778,880 bytes for 1,587 matches.

**The 2.2 GB matters.** The walk meets the non-addressable middle of the 64-bit
space, which returns the same error as the top of the space, and must continue
into the kernel's half above it. A walk that stops there examines 11 regions
totalling 156 KiB and must not report the enumeration as complete. The number is
recorded because it is the one a future change to the enumeration would move.

**Two engines, one plan, the same eight.** Run in the *same pass* over that
process, the compiled rule `FORENSIC-W11` and the regular expression
`FORENSIC-W1[0-9]` — upstream's `vadyarascan` and `vadregexscan` — report the
same eight addresses, sixteen rows in total, each naming the engine that found
it. A disagreement there would be in the planning or the attribution rather
than in either engine, which is the failure neither engine's own tests can see.
The regex route's own caveat is recorded with it rather than demonstrated
here: the match is against raw bytes and is Unicode-unaware, so an ASCII
pattern finds ASCII bytes and would not find the same characters stored as
UTF-16 — which is how many strings in a Windows process are held. Whether
*this* process also holds UTF-16 copies of its host name is not something
either of these two runs establishes, and neither claims it.

**Over an image's own space**, which is a different route and answers a
different question (upstream's `yarascan` over the physical layer). Pinned by
`win11_corpus_analysis::an_examiners_rules_search_a_reconstructed_hibernation_file`
and `seance_memory/tests/image_pattern_scan_swap_test.rs`, both `--release`:

| Image | Pattern | Matches | Coverage |
|---|---|---:|---:|
| The corpus `hiberfil.sys`, **reconstructed** | `HIBRMARK` | **131,110** with the ceiling raised; the shipped pass reports its 100,000-match ceiling | 2,258,956,288 B restored |
| The same file, **as a file** (declared raw) | `HIBRMARK` | **863** | 8,499,130,368 B |
| The corpus Linux **swap area** | `SWAPMARK` | **4,587** | 2,147,483,648 B, nothing unread |

**Three numbers for one question, and that is the point.** The machine marked
**65,536** pages before hibernating (`"HIBRMARK"` + the page index, one per
4 KiB of a resident 256 MiB buffer — `GROUND-TRUTH.txt`). The reconstruction
holds all 65,536, byte-exact, in 2,258,956,288 restored bytes (`VALIDATION.md`
`HIB-1`). A string search counts more than 65,536, because each marker page is
at two physical addresses and 38 occurrences sit inside other pages, most of
them the marker script's own source text. The shipped pass stops at its
100,000-match ceiling and says so. The compressed file holds 863
verbatim, because a block that did not compress is stored at its full size —
but those are offsets in a container, which cannot be placed in the machine's
memory and cannot be told from a page of an earlier hibernation. Only the
reconstruction's matches are at physical addresses.

The swap area's 4,587 is a fact about that file, not a count of the pages the
workload wrote (it wrote 4,096): a swap area is reused and holds slots from
earlier runs. Every match is at a 4 KiB boundary, which is what a slot is. The
record does **not** call those offsets memory addresses, and says why: nothing
in a swap area names a process, and a slot has no address until a page table
points at it. The richer answer is elsewhere — with the area *attached* to an
address space, a swapped page is read through the process's own page table and
a match in it is found in that process's context.

**What this baseline is for.** It is not a detection rule and there is nothing
to false-positive on: the rule is the examiner's. What the numbers pin is the
*planning and the reading* — how much of each process was covered, that nothing
mapped went unread, and that the addresses are the ones another tool reaches for
the same bytes. A number here that moves is either a change in what is planned
or a change in what is read.

---

### `windows`, `desktops` and `windowstations`: what the alternative to a refusal prints

Measured against Volatility 3.2.28.2 on
`test_data/win11_bitlocker/memory-unlocked.raw` (build 26200) with the same
`symbols/` directory every other entry here uses — `ntkrnlmp.pdb` and
`tcpip.pdb`, both derived from Microsoft's own PDBs. **No win32k PDB exists in
that directory, or anywhere on this machine**, which is the whole subject.

**The oracle, three plugins, measured:**

| plugin | rows |
|---|---|
| `windows.windowstations.WindowStations` | **14** |
| `windows.desktops.Desktops` | **0** (header only) |
| `windows.windows.Windows` (`tagWND`) | **0** (header only) |

Seven of the fourteen stations are names a Windows 11 machine really has:
`WinSta0` in session 0 and again in session 1, `Service-0x0-3e4$`,
`Service-0x0-3e5$`, `Service-0x0-3e7$`, `Service-0x0-322f2$` and
`msswindowstation`. The other seven are not names at all:

```
諬q                     (0x9b01d133fed0, 0x9b01d1709b70, 0x9b01d38c8c40)
靔©                    (0x9b01d1906b00, 0x9b01d1911d20)
뀀턫鬁￿苐첁￿蜠첁￿…      (0x9b01d5074178)
䒰ㇰ￿쀠㇮￿䨠㇮￿獐ㇲ￿…   (0x9b01c86b85a0 — 190 characters of pointer bytes)
```

Those are UTF-16 renderings of pointers and pool bytes: a pool candidate that
was accepted without validating that its name field is a name. Half the list is
noise, and nothing in the output tells a reader which half.

**What this build does instead.** `environment_desktops` walks stations and
desktops **only** when the symbol table it was given describes
`tagWINDOWSTATION` and `tagDESKTOP`, and returns `DesktopSurvey::Unsupported`
naming them when it does not — which on a kernel-PDB-only image is always. It
never enumerates `tagWND` at all, and says so on the survey and on every
desktop record (`windows_enumerated: false` with the reason), so an absent
window list cannot read as a desktop with nothing drawn on it.

**Why that is the better answer here, and the number that shows it.** The
capability this stage exists for is the hidden desktop: a process that calls
`CreateDesktop`, switches its thread there and draws windows nobody is looking
at. On this image the alternative implementation reports **zero** desktops and
**zero** windows — so it cannot answer that question either — while also
printing seven station names that do not exist. A refusal that says "this needs
a symbol table describing tagWND for this build" costs an examiner nothing they
had; a station list half of which is fabricated costs them the ability to trust
the other half.

**What would change it.** A `win32kbase.pdb`/`win32kfull.pdb`-derived ISF for
build 26200, at which point the existing symbol-table-driven walk runs with no
code change, and the `tagWND` chain becomes implementable against a layout
rather than against a guess. `ROADMAP` §5.3 prices that separately and
`seance_symbol_fetch` is the route to the PDB; fetching one needs the network
and a decision nobody here has taken.

### `strings` over memory: a frame two processes map names both

**The answer.** `KUSER_SHARED_DATA` is one physical frame mapped into every
live user process at the fixed virtual address `0x7FFE0000`. On this capture
that frame is physical **`0x285000`**, and a strings offset inside it —
`0x285040` — is attributed to **125** address spaces, each at the virtual
address it has there.

**Why it is a known answer and not a self-check.** Ground truth comes from the
*other* walker. `PageWalk::translate` — the upward walk, tested on its own
against hand-built hierarchies — is asked for `0x7FFE0000` in each process's own
address space and answers with the same physical frame every time; the test
asserts that agreement before it asks the reverse mapping anything. The
criterion `ROADMAP` §5.3 set for this route is that *a physical offset inside a
page mapped by two processes must name both*, and this is that criterion on real
evidence with the answer fixed by the Windows ABI rather than by this code.

**What the run costs**, on the same capture (130 processes, one offset):

| | |
|---|---|
| Tables read | 43,006 (176 MiB) |
| Prototype-PTE hops | 328,132, of which 168,438 did not resolve |
| Subtrees declined as the kernel's own | 5,938 |
| Wall time | 0.9 s, `--release` |
| Address spaces reporting short coverage | 129 of 131 |

The last row is the honest one and does not improve with effort: every address
space on a live Windows machine has suppressed uniform page tables and trimmed
shared pages in it, so the verdict for a frame with owners here is *mapped, and
coverage was short* rather than plain *mapped* — and an offset with **no** owner
is never reported as unmapped at all.

**The alternative implementation gets this wrong, measured.** Volatility 3
2.28.2's `windows.strings` unpacks `Intel.mapping()`'s tuple in a different
order in its per-process branch than in its kernel branch
(`strings.py:183-191` against `:150-155`), so its process entries are keyed by
the **virtual** page number. Run on this image with offsets taken
from pages `lsass.exe` (968), `explorer.exe` (4312) and `winlogon.exe` (888)
really map:

```
D_LSASS_PRIVATE_phys_0x1247b3000     0x1247b3000   FREE MEMORY
E_LSASS_PRIVATE_phys_0x260845000     0x260845000   FREE MEMORY
G_EXPLORER_PRIVATE_phys_0x16691c000  0x16691c000   FREE MEMORY
K_WINLOGON_PRIVATE_phys_0x269562000  0x269562000   FREE MEMORY
C_KUSER_VPN_0x7ffe0...               0x7ffe0000    Process 6084:0x285000, … (123 processes)
I_NTOSKRNL_BASE_phys_0x100400000     0x100400000   kernel:0xeffc014fd000, kernel:0xf8029fa00000
```

Every genuine physical offset returns `FREE MEMORY`. Physical `0x7ffe0000`
returns 123 of the 130 live processes — not because they map that frame, but
because `0x7ffe0` is `KUSER_SHARED_DATA`'s *virtual* page in each of them; and
6,126 of one process's 330,040 keys are low enough to collide with a real
physical page, so that many physical frames of this image can be falsely
attributed to that one process. Only the kernel column is correct. The run took
10 m 40 s.

**Test.** `a_physical_offset_two_processes_map_names_both_of_them` in
`seance_plugin_memory_windows/tests/win11_corpus_analysis.rs`, release-only.

## Images: the Malware Cookbook and Stuxnet XP captures — the legacy timer table and the first orphan-thread answer

Pinned by `seance_plugin_memory_windows/tests/legacy_xp_corpus.rs`
(`--release`; `SEANCE_COOKBOOK_MEM`, `SEANCE_STUXNET_MEM`, and
`SEANCE_SYMBOL_DIRS` pointing at the extracted Volatility Windows symbol pack).
The images are **not redistributable** and hold live malware; they were
unzipped to a scratch directory, read as data, and deleted. Provenance and
hashes: `~/forensic_corpora/malware_cookbook_mem/PROVENANCE.md` and
`~/forensic_corpora/stuxnet_mem/PROVENANCE.md`.

Two kinds of answer, and each row says which. **Published**: M. H. Ligh's
2011 write-ups of these same files. **Volatility**: Volatility 3 2.28.2 run on
the same files as an oracle (`windows.info`, `windows.timers`,
`windows.orphan_kernel_threads`, `windows.unloadedmodules`,
`windows.debugregisters`) — `vol.py -q -r csv -s <pack> -f <image> <plugin>`.
The venv under `reference/volatility3/.venv` carries a macOS interpreter path;
on this host it runs as `PYTHONPATH=.venv/lib/python3.14/site-packages:. python3 vol.py`.

| Image | Kernel (`windows.info`) |
|---|---|
| `tigger`, `be2`, `zeus` | `ntkrnlpa.pdb` `BD8F451F3E754ED8A34B50560CEB08E3-1`, 2600.xpsp_sp2_rtm.040803-2158, PAE, 1 processor, base 0x804d7000 |
| `stuxnet` | XP SP3 `ntkrnlpa.pdb`, PAE, base 0x804d7000 |

### `timers` on the legacy global table

| Measurement | tigger | be2 | zeus | stuxnet | Source |
|---|---:|---:|---:|---:|---|
| Shape / bucket entry | legacy / bare `_LIST_ENTRY` | same | same | same | ISF |
| Buckets derived | **256** | 256 | 256 | 256 | Séance; Volatility hardcodes 256 for XP x86 |
| Next symbol above the head | `KiDispatcherReadyListHead`, +2,048 B | same | same | same | ISF |
| Timers read | 233 | 227 | 242 | 176 | Séance |
| Timers carrying a DPC | **60** | **60** | **64** | **58** | = Volatility's row count |
| Same `_KTIMER` set, routine and period as Volatility | 60/60 | 60/60 | 64/64 | 58/58 | Volatility |
| Routines outside every loaded module | 0 | 0 | 0 | 0 | both |

**Three build-specific facts the XP read established.** (1) XP declares no
`_KTIMER_TABLE_ENTRY`: on NT 5.1 each bucket is a bare `_LIST_ENTRY`
(`a_legacy_table_of_bare_list_heads_is_walked_with_the_list_entry_stride`).
(2) The table's extent is bounded by the next symbol the build declares: the 32
`_LIST_ENTRY` heads of `KiDispatcherReadyListHead` follow the table and are
self-referential when empty, so a heads-only stopping rule would walk scheduler
ready lists as timer buckets
(`the_legacy_extent_is_bounded_by_the_next_declared_symbol`). (3) `_KTIMER.Period`
is declared `long` on XP, and an unsigned-only read drops all 12 periods
(`a_period_the_build_declares_signed_is_read`).

**The bound across the pack.** Of the 926 ISFs among `ntkrnlmp`, `ntkrnlpa`,
`ntkrpamp` and `ntoskrnl` that declare `KiTimerTableListHead`, 349 declare no
`_KTIMER_TABLE_ENTRY`. The next-symbol bound equals the documented 256 (bare,
x86) or 512 (declared entry) on 867 of the 926; on the other 59 it is 1,024 or
768 or absent, and there the probe decides alone.

**Declared-entry form:** read from evidence on Server 2008 SP1 only, below. Not read:
Server 2003 SP1+, Vista and XP x64. The
NIST CFReDS "Basic Memory Images" RAR opens with 7-Zip 23.01. Its
`boomer-win2003-2006-03-17.img` is Server 2003 **RTM** (3790.srv03_rtm, x86),
whose ISF declares no `_KTIMER_TABLE_ENTRY`: 256 bare buckets (bounded by
`KiBiosFrame` at +2,048), 156 timers, 43 with a DPC = Volatility's 43 in
address, routine and period, 0 outside a module. Pinned by
`the_server_2003_rtm_legacy_table_matches_volatility` in
`seance_plugin_memory_windows/tests/legacy_xp_corpus.rs`, which asserts every
number here and holds Volatility 3's 43 `(_KTIMER, routine, period)` rows from
a `windows.timers` run; the image is extracted with `~/.local/bin/7zz`
and named by `SEANCE_NIST_BASIC_MEM` (SHA-256 of the extracted member
`dc7022c2183dade6c36ebf19c74af5234bff8800e2a6f95e825287da9a214adb`). Its
`vista-beta2.img` needs
`ntkrnlmp.pdb` `5B71B326D7C84B88B623F8F1026BE689-2`, which no pack here holds —
an evidence bound.

`memdump.mem` (Windows Server 2008 SP1 x86 PAE, SHA-256
`d3b13f2224cab20440a4bb3c5c971662be6e61f431340f319cef7312bb6177f4`) declares
`_KTIMER_TABLE_ENTRY`; `KiTimerTableSize` read from the image is **512** (dword at physical
0x01971b30) and Séance walks 512 buckets. The 14 `(_KTIMER, routine, period)` rows of Volatility
3.2.28.2 `windows.timers` are set-equal with Séance's timers from buckets 0 to 255 (Volatility
reads 256 buckets only, `_LIST_ENTRY` stride on a 16-byte entry). Séance finds 41 further DPC
timers in buckets 256 to 511, all in loaded modules, pinned and ungraded. Rows:
`seance_plugin_memory_windows/tests/legacy_xp_corpus.rs`,
`the_server_2008_declared_entry_legacy_table_matches_volatility`. `VALIDATION.md` MEM-XP-4.

### The thread groups, `unloadedmodules`, and the first published true positive

| Measurement | tigger | be2 | zeus | stuxnet | Source |
|---|---:|---:|---:|---:|---|
| Threads examined | 365 | 360 | 370 | 368 | Séance |
| Orphan kernel-thread rows | **3** | 0 | 0 | 0 | = Volatility |
| Graded orphan findings | 0 | 0 | 0 | 0 | Séance (by design, below) |
| Unloaded-driver records | 10 | 9 | 10 | 16 | = Volatility, names and ranges |
| Debug-register rows | 1 | 1 | 1 | 1 | Séance (Volatility prints none; see below) |

**`tigger.vmem`'s orphan thread — Published and Volatility.** Ligh
(*Investigating Windows Threads with Volatility*, 2011-04-18) prints `ETHREAD
0xff1f92b0 Pid 4 Tid 1648 … StartAddress 0xf2edd150`. Séance publishes that
row exactly — Pid 4 (System), Tid 1648, thread 0xff1f92b0, start 0xf2edd150,
`outside_any_module`, kernel thread by `_KTHREAD.SystemThread`, not terminated,
inside no unloaded driver's range — and the two others Volatility 3 prints
(Tid 1720 at 0xf2edc54e, Tid 1992 at 0xf2edba46). **All three are
observations, not graded findings**: XP declares no
`_ETHREAD.StartAddressInvalid`, so that exclusion is `not_assessed` and the
group grades nothing on this build, exactly as it is designed to. The signal
fires on the known answer; the grade is withheld for a stated reason. (The 2009
post that shows *other* tigger TIDs is of a different, earlier capture.)

**`unloadedmodules`** read through the documented x86 layout (this ISF declares
no `_UNLOADED_DRIVERS`), which the record still marks `unvalidated`; on these
two builds it agrees with Volatility on every name, range and slot.

**`debugregisters` on XP.** The registers are read at their declared width on
x86, where the ISF declares them `unsigned long` (an eight-byte read gives `Dr0`
as 0x0000000200000001, which is `Dr1:Dr0`), and XP's `_KTHREAD.DebugActive` is
looked for
(`an_x86_builds_debug_registers_are_read_at_their_declared_width`,
`an_nt5_builds_kthread_debug_active_is_the_threads_own_claim`). Every
capture shows one `winlogon.exe` thread (tigger Tid 636; stuxnet Tid 628) with
`DebugActive` 0x8f / 0x8d — the low four bits exactly the slots holding a
non-zero address — `Dr7` 0x555 (L0–L3 enabled), `Dr6` 0xffff0ff0 and `Dr0`–`Dr3`
= 1, 2, 1, 0xa (SP2) / 0xa0, 0, 3, 0xb0 (SP3): null-page addresses nothing
executes from. The row reports a confirmed armed breakpoint on four of four XP
captures, three of whose malware has nothing to do with winlogon. **That is a
false positive of this group on XP, not a true positive**. Volatility 3's `windows.debugregisters` reads the same thread past
its `Dr7`/`Dr0`-`Dr3` filters and drops it because no address lands in a
file-backed VAD.

**A breakpoint armed only in the null page is not graded.** Séance's own rule: a row is graded as an armed breakpoint only
when at least one address `Dr7` arms is at or above 0x10000
(`MM_LOWEST_USER_ADDRESS`, WDK `wdm.h`). The winlogon row is still published,
with its four addresses, `armed_only_in_the_null_page: true` and a
`not_graded_reason`. Clean-capture false positives (`threads_with_a_breakpoint`):

| Capture | False positives |
|---|---:|
| `tigger.vmem`, `be2.vmem`, `zeus.vmem` (XP SP2) | **0** each |
| `stuxnet.vmem` (XP SP3) | **0** |
| Windows 11 26200 `memory-unlocked.raw` | 0 |
| LoneWolf `memdump.mem` (Windows 10) | 1 published, 0 graded (see the `ActiveDR7` rule below) |
| 13Cubed `mini_memory_ctf` `memdump.mem` (Windows 10) | 0 |
| Case 001 `DESKTOP-SDN1RPT.mem` | 0 |
| Case 001 `citadeldc01.mem` | 0 |

The LoneWolf row is untouched by this rule — its armed addresses are not in the
null page — and is not a true positive either: a `RuntimeBroker.exe` thread
with Tid 0, `DebugActive` = 2 and register values that read as pool bytes
(`Dr1` 0x65536d4d02060005).

**Only `ActiveDR7` confirms where the build declares it.** `DebugActive` = 2 is `Instrumented` (bit 1 of the same byte on Windows
10), not `ActiveDR7` (bit 0). Confirmed rows / graded rows:
XP ×4 and Server 2003 RTM 1/0 each (no `ActiveDR7` declared); Windows 11
0/0; **LoneWolf 1/0**; **13Cubed 5/0**; Case 001 DC 1/0
(a Tid-0 row with nothing armed); Case 001 Desktop 0/0. Pinned by
`a_debug_active_byte_set_by_another_flag_is_not_confirmation`,
`the_active_dr7_bit_is_read_where_this_build_declares_it`,
`a_breakpoint_on_a_thread_with_tid_zero_is_published_and_not_graded` and
`a_breakpoint_on_a_non_canonical_address_is_published_and_not_graded`.

### The Cookbook's other five captures

`coreflood`, `laqma`, `prolaco`, `sality`, `silentbanker` (XP SP2 PAE, same
kernel as tigger), unzipped outside the repository and deleted after the run.
Oracle: Volatility 3 2.28.2 `windows.timers`, `windows.unloadedmodules`,
`windows.orphan_kernel_threads`, `windows.debugregisters`; its rows are copied
into `seance_plugin_memory_windows/tests/legacy_xp_oracle/cookbook_volatility.rs`.
**No published answer ties any of the five to these groups** (they are the
book's user-mode recipes), so every row below is agreement with Volatility or
a measured count, never a true positive or a true negative.

| Measurement | coreflood | laqma | prolaco | sality | silentbanker | Source |
|---|---:|---:|---:|---:|---:|---|
| Timer buckets | 256 | 256 | 256 (12 torn) | 256 | 256 | Séance |
| Timers on the table | 176 | 190 | 140 | 242 | 175 | Séance (Volatility drops DPC-less timers) |
| With a DPC | 62 | 63 | 50 | 61 | 62 | = Volatility rows; prolaco see below |
| Routine outside every module | 0 | 0 | 0 | 0 | 0 | Séance |
| Unloaded-driver records | 11 | 10 | 12 | 10 | 10 | = Volatility, names, ranges, slots |
| Orphan kernel-thread rows | 0 | 0 | 0 | 0 | 0 | = Volatility (none) |
| Debug-register rows (graded) | 1 (0) | 1 (0) | 1 (0) | 1 (0) | 1 (0) | winlogon null-page row; Volatility none |
| Suspended threads (findings) | 1 (0) | 1 (0) | 0 | 0 | 1 (0) | one `VMUpgradeHelper` thread, count 1 |
| ETW processes assessed | 0 | 0 | 0 | 0 | 0 | every process unassessed; the reason was not checked and the corpus test asserts only the count. The refusals the code can give are an unwalkable loader list, no `ntdll.dll`, an unreadable export table, or "the export table does not name them or their pages are not resident". XP's ntdll is not expected to export `EtwEventWrite` (a Vista-era export), but that was not confirmed here |
| `lsass` examined (Skeleton Key) | 0 | 0 | 0 | 0 | 0 | unassessable, as on the other XP captures |

**`prolaco.vmem` is torn.** Twelve of its
256 bucket heads (37, 70, 99, 101, 199, 201, 202, 204, 209, 211, 224, 252) have
a first link whose `Blink` names a different bucket; the heads were read by
hand through the PAE tables (DTB 0x319000) to confirm it. The extent probe does
not stop at such a head, and bucket 68's head at 0x80552420 is not read as a
`_KTIMER` at 0x80552408. The figures above stand. Séance's
50 DPC timers are Volatility's 55 rows less four timers Volatility prints twice
(0x80ee1730, 0x80ff0d58, 0x81027c30, 0xff1ef230 — reached from two joined
lists) and the one it gets wrong, 0x80552408, a bucket head that Volatility
prints with no module and a period of -2141903832. Pinned by
`a_torn_bucket_head_does_not_end_the_legacy_table`.

### `suspicious_threads`: observed, not known

No published answer names a user thread started in injected memory on the
Cookbook or Stuxnet captures, so these are observations compared with Volatility
3.2.28.2, not known answers: be2 1, zeus 10, stuxnet 9 findings, each also a
Volatility row. Volatility's extra rows (be2 4, zeus 13, stuxnet 25 in all) are
XP `Win32StartAddress` values that are LPC message ids (`LpcReceivedMsgIdValid`
set) or zero. The clean Windows 11 build 26200 capture gives 0 over 123
processes, and its record is **incomplete**: 76 of its 78 kernel-mode starts are
on threads whose `SystemThread` bit is clear, which no stage judges (2 are on
kernel threads). Procedure and table: `documentation/VALIDATION.md`, MEM-THR-1.

## Image: `tamper-plant.raw` (Windows 11 25H2, planted user-mode tamper) - SYNTHETIC

`~/forensic_corpora/win11_tamper_plant/tamper-plant.raw`, SHA-256
`6a2c583db52818965c3d9a5972c6ce583e9a6ddba5e185eebd80f904682c9fa7`. The answers are what
`test_data/win11_tamper_plant/plant.ps1` printed inside the guest (`plant-truth.json`), not a
laboratory's published result. Test: `seance_plugin_memory_windows/tests/win11_tamper_plant.rs`.

| Planted | Answer |
|---|---|
| `EtwEventWrite` := `c3` | pid 1788, `0x00007ffc7dc0e470`, route `both` |
| `EtwEventWrite` := `33 c0 c3` | pid 4696, `0x00007ffc7dc0e470`, route `both` |
| Dr0 / Dr7 = 1 | pid 1428, tid 2640, slot 0 at `0x00007ffc7cdcaf90`; the only thread with a breakpoint |
| suspended thread | pid 4868, tid 1332, listed, never a finding |
| everything else | 0 ETW signals beyond the two above |

## Images: encoded timer DPCs on x64 — Case 001, 13Cubed, Windows 11

Pinned by `seance_plugin_memory_windows/tests/case001_corpus.rs`
and `win11_corpus_analysis.rs` (`--release`), graded against Volatility 3
2.28.2 `windows.timers` (offsets compared canonicalised). Every x64 build here
declares `KiWaitNever`/`KiWaitAlways`; each `Dpc` field was decoded and
checked against the build's `_KDPC.Type` / `_KOBJECTS` values.

| Image | Timers: distinct / sightings | With a DPC | Unreadable | = Volatility (timer, routine, period) | Outside every module |
|---|---:|---:|---:|---:|---:|
| Windows 11 26200 | 209 / 209 | 52 | 0 | 52/52 | 0 |
| Case 001 `citadeldc01.mem` (2012 R2) | 179 / 196 | 39 | 2 | 39/39 | 0 |
| Case 001 `DESKTOP-SDN1RPT.mem` (Win 10) | 187 / 245 | 38 | 3 | 38/38 | 0 graded; 1 timer PatchGuard-shaped, ungraded |
| 13Cubed `memdump.mem` (Win 10) | 197 / 265 | 49 | 8 | 49/49 | 0 |

"Unreadable" rows decode to a non-canonical value; Volatility prints none of
them. Counts are of distinct `_KTIMER`s, and the sightings are `rows_walked`: a
timer can be reached from two bucket lists. Timers reached from two lists with
no mechanism the walk saw: DC 8 of 12, desktop 16 of 27, 13Cubed 21 of 33. Lone
Wolf (ungraded) reads 246 / 342, 50 with a DPC, 5 unreadable. The Desktop's
signal is one unaligned `_KTIMER` (0xffffbe8e7105d5ab) whose `_KDPC` sits at
+0x40, routine 0xffffbe8e70b622b1 in pool and `DeferredContext` non-canonical.
Volatility prints it with no module; the shape is PatchGuard's own timer. A row
with all three conditions is published `patchguard_shaped` and not graded: the
Desktop reads 0 outside every module and 1 timer PatchGuard-shaped, published
once (187 distinct timers, 38 with a DPC; the shaped timer's `reached_from`
names both buckets), pinned as `patchguard_shaped == 1` in `case001_corpus.rs`.
Windows 11 26200, `citadeldc01.mem`, 13Cubed and LoneWolf read 0 and 0.
Eleven further captures (distinct timers / rows walked / with a DPC / unreadable;
all 0 graded, 0 shaped): `memdump-001.mem` 452 / 611 / 85 / 79; Windows 11 26200 console VM 157 / 157 / 53 / 0
and VeraCrypt VM 168 / 168 / 52 / 0; Server 2008 x86 173 / 192 / 57 / 0; `0zapftis.vmem` 205 / 205 / 55 / 0;
Cookbook `coreflood` 176 / 176 / 62 / 0, `laqma` 190 / 190 / 63 / 0, `prolaco` 140 / 148 / 50 / 0, `sality`
242 / 242 / 61 / 0, `silentbanker` 175 / 175 / 62 / 0; `boomer-win2003` 156 / 156 / 43 / 0. These are Séance's
own measurements, not an answer key; the Vista M57 capture is refused at discovery and not measured
(`VALIDATION.md`).

Pinned by `a_breakpoint_armed_only_in_the_null_page_is_published_and_not_graded`
and `an_armed_address_outside_the_null_page_is_still_graded`, and on the XP
captures by `legacy_xp_corpus`.

**Still without a true positive:** `timers` (no routine outside a module on any
capture here), `unloadedmodules` as a signal (no orphan or timer address falls
in an unloaded range), `debugregisters` (zero graded on XP, above),
`suspended_threads` (no non-zero count
on any capture), `etwpatch` (every process is unassessed: none of the four ETW
exports reads from any ntdll — XP's ntdll predates `EtwEventWrite`, and the
record does not distinguish that from non-residence) and `skeleton_key_check`
(the `lsass.exe` examined has `cryptdll.dll`'s headers paged out on all four). `be2`'s published answer is SSDT hooks, not one of
these groups.

## Images: MMUShell AArch64 Linux dumps — the ARM64 translation core

Pinned by `seance_memory/tests/arm64_mmushell_real_test.rs`
(`SEANCE_MMUSHELL_AARCH64`, a directory holding `linux/linux.dump` and
`debian/linux.dump` from the dataset's `aarch64/linux.7z` and
`aarch64/linux_debian.7z`). Oliveri & Balzarotti's MMUShell dataset (ACM TOPS
2022): **QEMU-emulated guests, not ARM64 hardware**; 4 GiB of RAM at physical
0x40000000; no symbols. The ground truth is the register trace QEMU recorded
(`linux.regs`, a Python pickle, read with `pickletools` and a symbolic reader,
never unpickled); the independent answer is a Python stage-1 walker written
from ARM DDI 0487 D8 without reference to this crate's walker.

| | linux | debian |
|---|---|---|
| `TCR_EL1` in force at the end | `0x32b5593519` | `0x400032b5503510` |
| `TTBR1_EL1` | `0xe6000040755000` | `0x42e0000412ee000` |
| `TTBR0_EL1` walked | `0x139de0000` (the last, live) | `0x13d142000` (latest that maps anything) |
| Granule / VA bits | 4 KiB / 39 (T1SZ = T0SZ = 25) | 4 KiB / 48 (16) |
| `IPS` / `PARange` | 40-bit / 44-bit | 40-bit / 44-bit |
| `TBI0` / `TBI1` / `DS` | 1 / 0 / 0 | 1 / 0 / 0 |
| Kernel leaves (4K / 2M / 1G) | 2,383 / 544 / 3 | 6,125 / 1,183 / 2 |
| Process leaves (4K) | 264 | 1,159 |

**Every one of the 11,663 leaves agrees** — counts by size and an
order-independent digest over `(va, pa, size)` — plus 69 hard-coded interior
translations (address and page/block size) and 64 faults (level, entry value
and entry address). No defect was found. The trees use the contiguous bit,
DBM, PXN/UXN, nG and Linux's software bits 58:55, and none confused the walk.

**What this does not exercise:** 16 KiB and 64 KiB
granules; LPA/LPA2; 52-bit VAs; any non-zero invalid descriptor (no swap or
`PROT_NONE` entry exists in these trees); `APTable` (not read: no access
permission of any level is reported); `HA`/`HD`. The regimes are built from
the recorded `TCR_EL1` values by `Arm64Regime::from_tcr_el1`, and the test
also decodes `TG`/`TxSZ` by hand and asserts the two agree. TBI is honoured
when the regime records it: every `TTBR0` spot address tagged `0x2a`
translates to the oracle's physical address under `TBI0 = 1`, and a tagged
kernel pointer is still `NonCanonical` under `TBI1 = 0`. `IPS` is enforced and
`PXNTable`/`UXNTable` are folded into `no_execute` unless `HPDn` is set, but
**no real descriptor meets either** (no output address above 40 bits, no
table descriptor sets bits 63:59), so both are pinned on synthetic tables
only. The kernel root is found from the bytes on the debian dump — from
the kernel's own `VMCOREINFO` (this file's corpus table) — but no arm64 symbol
table is held, so no arm64 Linux profile is built on either dump.

## Linux symbols recovered from the capture itself

Gated on `SEANCE_LINUX_MEM`, which names a directory holding an AVML capture of a
live Linux host **plus `vmlinux.btf` and `kallsyms.txt.gz` from the same boot**.
Same boot is not a convenience: KASLR moves every address on restart, so a
kallsyms file from a later boot proves nothing about this image.

This is the **host-attested** class of answer. The machine stating what its own
symbol table held is strong corroboration; it is not a laboratory's published
result, and `seance_validate`'s MEM-1 case says so on its face rather than
rendering the two alike.

| What is checked | Against | Test |
|---|---|---|
| BTF recovered from the capture | That host's `/sys/kernel/btf/vmlinux`, member for member (~6 MB describing 334,040 types on Ubuntu's 6.8) | `btf_real_capture_test.rs` |
| BTF → ISF → `SymbolTable`, through the ordinary admission gates | 5,000+ member offsets against the BTF they came from | `btf_symboltable_test.rs` |
| kallsyms recovered from the capture | `/proc/kallsyms` from the same boot — every recovered symbol must carry the address the kernel printed for that name | `kallsyms_real_capture_test.rs` |
| The AVML container itself | A capture AVML wrote, not a fixture this project generated | `avml_real_capture_test.rs` |

The AVML case uses an input this project did not write, as `documentation/TESTING.md`
requires: `end` in an AVML block header is **inclusive**, which a fixture written by
this project can get backwards.

Both BTF tests sweep the whole image and take about a minute; run them
`--release`.

## Suspicious threads

Observed on six held captures and compared with Volatility 3 2.28.2 `windows.malware.suspicious_threads`; no published
key names an injected user thread in any of them (`VALIDATION.md` `MEM-THR-2`). The pinned counts live in
`seance_plugin_memory_windows/tests/case001_corpus.rs`.

| Capture | Findings | Note |
|---|---:|---|
| samsclass Server 2008 (clean) | 0 | 3 gaps, a swapped-out `_FILE_OBJECT` |
| CFReDS Server 2003 (clean) | 0 | 24 starts are LPC message ids, not placed |
| LoneWolf Windows 10 | 0 | |
| 13Cubed mini-memory | 0 | planted process is not a thread injection |
| Case 001 domain controller | 1 | spoolsv 3724 / 2508, private RWX |
| Case 001 desktop | 1 | powershell 3316 / 3892, private RWX; Volatility prints the same thread |
