# Container Format Support

Seance supports multiple forensic disk image container formats for ingesting evidence. This document describes the supported formats and their capabilities.

## Overview

Container formats encapsulate raw disk images with compression, checksums, and metadata. Seance provides transparent access to the underlying data through its DataSource abstraction.

**Supported Formats:**
- ✅ **E01/EWF** - Production-ready (libewf; behind the optional `e01` cargo feature, on by default)
- ✅ **AFF4** - Production-ready reader (chunked ImageStream, snappy/deflate, striped containers)
- ✅ **VHD / VHDX / VMDK / QCOW2** - Virtual disk images (`seance_container_vdisk`)
- ✅ **Apple `.sparseimage`** - Band-mapped single-file sparse disk image (`seance_container_sparseimage`)
- ✅ **ZIP** - Standard archive extraction (`seance_container_zip`)
- ✅ **gzip / bzip2 / xz / 7z / tar / OLE2** - Compressed-stream, archive and compound-file expanders (`seance_container_archive`)
- ✅ **RAW** - Direct disk image access
- ⚠️ **Optical disc images: ISO 9660 and UDF** - ISO 9660 / Joliet / Rock Ridge (`seance_plugin_iso9660`); UDF on physical, virtual (VAT), sparable and metadata partitions, on 512-, 2,048- and 4,096-byte sectors (`seance_plugin_udf`; graded on one real UDF 1.02 disc, and on self-made UDF 1.50, 2.01 and 2.50 volumes, not real burned discs). See **Optical disc images** below
- ✅ **RAID 0/1/5/6 / JBOD / LVM2** - Multi-member reassembly into one logical device (`seance_container_raid`; reached from the CLI, not from the module pipeline)
- ✅ **pcap / pcapng network captures** - Flow, DNS and provenance records from a packet capture (`seance_plugin_pcap`; see **Network captures** below for exactly what is and is not decoded)

**Encrypted volumes** are a separate axis from container format, and this
document owns them too, because "which formats are supported, and to what
depth" is exactly the question a locked volume asks:

| Scheme | Detected without a credential | Reported without a credential | Decrypted with a credential |
|---|---|---|---|
| **BitLocker** (`seance_plugin_bitlocker`) | ✅ | ✅ cipher, volume identifier, key-protector labels | ✅ AES-XTS 128/256 and AES-CBC+diffuser 128/256; plain AES-CBC recovers keys only |
| **LUKS1 / LUKS2** (`seance_plugin_luks`) | ✅ (`is_luks`) | ✅ version, cipher, UUID (LUKS1), active-keyslot count + the incompleteness pair | ✅ AES-XTS only |
| **APFS FileVault** (`seance_plugin_apfs`) | ✅ | ✅ volume record stamped `encrypted: true`, filesystem walk skipped | ❌ not implemented |
| **Apple encrypted disk image** (`encrcdsa` `.dmg`) | ✅ magic at ingest | ✅ source stamped `encrypted` / `encryption_format` + the incompleteness pair | ❌ not implemented |

LUKS and BitLocker now take the same decision: detection is not conditional on
holding the key. `LuksDecryptor::process` tests `is_luks` before it looks at the
passphrase, and a LUKS volume in a run without `--luks-passphrase` produces a
`VolumeDecryption` record (`subtype: detected_locked`, `status: NotUnlocked`)
carrying `content_incomplete`/`inventory_incomplete` with reason `encrypted`,
which puts it on the Needs attention queue. That queue row takes the
passphrase — or, for BitLocker, the recovery password or the password — for
that one volume through `POST /cases/{id}/artifacts/{id}/credential` (or the
REPL's `/unlock`), and the decryptor runs again on the volume alone. An accepted
credential puts the decrypted volume beneath the locked one with a
`VolumeDecryption` record of `status: Unlocked` (naming `credential_kind` and
`credential_source`, never the value), which supersedes the locked record; a
rejected one records nothing and leaves the locked record standing, and the job
and the audit log say it was refused. A volume decrypted in memory is not
re-readable from the evidence afterwards — the key is not retained — so the
content resolver refuses to serve it or anything beneath it rather than serve
ciphertext.

The encryption detector (`plugin.analysis.encryption_detector`) also writes a record for a
LUKS volume — "LUKS encrypted partition detected". The two are tied together:
both carry the volume's artifact id as `volume_artifact_id` (as does the decrypted child
volume), and the detector's record names `plugin.crypto.luks_decryptor` in
`unlock_status_reported_by` with a sentence saying that the decryptor's record, not this one,
states whether the volume was unlocked. The detector's record carries no incompleteness pair
of its own, so the volume is listed on the Needs attention queue once.

BitLocker is tied the same way. The detector's record for a `-FVE-FS-` volume —
"BitLocker Drive Encryption detected (BDE boot sector)" — carries `volume_artifact_id`, names
`plugin.crypto.bitlocker_decryptor` in `unlock_status_reported_by`, and carries an
`unlock_status_note`; every record the BitLocker decryptor writes for the volume
(`detected_locked`, `unlock_failed` with `UnlockFailed` or `CipherNotDecryptable`, and the
decrypted child volume) carries the same `volume_artifact_id`. The detector's record still carries
no incompleteness pair, so the Needs attention entry is the decryptor's, unchanged. A BitLocker
To Go volume reads `MSWIN4.1` at offset 3, so the detector writes no record for it and the
decryptor's is the only one. Pinned on the real Windows 11 XTS-AES-256 system volume (detector
and decryptor) and on `test_data/bdetogo.raw` (locked, failed and decrypted).

---

## Media containers (MP4, M4A, M4V, MOV, 3GP)

`seance_plugin_media` reads the ISO base media file format's `moov/mvhd` movie header for what
a case asks of a recording: **how long it runs**, and **when the device wrote it**. It is read
from the header rather than inferred from the file's own timestamps, which on an archive- or
folder-sourced case describe the copy rather than the recording.

Two traps the reader is explicit about:

* **The epoch.** ISO-BMFF counts seconds from 1904-01-01 UTC. Read as a Unix time every media
  file in a case is dated 66 years early; the reader converts.
* **The zeroes.** A writer with no time to store writes 0, and a file whose `moov` was never
  written — an interrupted recording — has no duration at all. The first is left absent rather
  than becoming 1904; the second is declared with the standard incompleteness pair rather than
  reported as a recording of zero seconds.

A file is claimed on its `ftyp` brand, never on its name. Not read yet: MP3 (frame-header
walking), Matroska/WebM, and per-track detail (codec, resolution, channel layout).


## E01/EWF Format (EnCase Evidence File)

### Status: ✅ Production Ready

The E01 format is the industry-standard forensic disk image format created by Guidance Software (EnCase). Seance provides full production support via FFI bindings to libewf.

### Features

**Format Support:**
- Multi-segment sets, as libewf's own `glob` returns them (`.E01`, `.E02`, …
  `.E99`, `.EAA` … `.EZZ`, and the SMART `.S01` family; a set named in lower case
  — `.e01` … `.e99`, `.eaa` … — is read the same way, and mixed-case letter pairs are not segments)
- Automatic segment detection and loading — libewf's, from the first segment
- Compression (zlib/deflate) with transparent decompression
- Adler32 chunk checksums, verified inside libewf

**What this module does about a bad chunk:** it refuses zero-substitution at
open (`libewf_handle_set_read_zero_chunk_on_error` is set to 0 and its return
code checked, so an image on which libewf will not accept the request does not
open at all), and a chunk libewf cannot decode then reaches the caller as an
I/O error carrying libewf's own words. There is no *recovery*: nothing here
retries, reconstructs or substitutes. Detection is libewf's; the decision this
crate takes is to let the error through rather than serve zeroes that cannot be
told from a region which held zeroes.

**What the name gate does and does not accept:** three ASCII characters, first
`E`, `S` or `L`, then two digits other than `00` (numbering starts at one, and
`seance_core`'s own segment ordinal refuses `.E00` on the same ground) or two
**uppercase** letters. So `.exe`, `.eml` and `.epub` stay out of the parsing
path — and a set continuing past `.EZZ` into the `FAA`…`ZZZ` names is **not**
recognised by name, nor is any four-character EWF2 extension (`.Ex01`,
`.Lx01`). Those reach the module only when content detection has already
labelled them, and that check takes the three bytes `EVF`, or all eight bytes of
the logical signature `LVF\x09\x0d\x0a\xff\x00`.

**Logical evidence files (`.L01`) are walked, not imaged.** The file's own first eight bytes decide it:
`LVF\x09\x0d\x0a\xff\x00` is a container of files and their metadata, not an
image of a device, so its media stream (EnCase's packing of the entries' data) is
never published as raw evidence. Instead libewf's `file_entry` API walks the
entry tree — in the isolated `seance-ewf-helper --logical` process by default,
in process only when isolation is off or the helper is absent, exactly as for an
image — and every entry is published as a `FileEntry` whose bytes are read by
`libewf_file_entry_read_random`. A physical image that merely happens to be named
`.L01` still opens as a disk: the decision is by signature, never by name.

Content detection routes a bare `.L01` here by that full eight-byte signature.
`.l01` is in no extension map, so a file whose
first bytes cannot be read does not reach the module.

**What the walk reads, per entry:** the UTF-8 name (a declared name over 64 KiB
is not read), the type (`d` directory, `f` file), the flags, the size, the media
data offset/size and duplicate offset, the four times the L01 records —
`creation_time`, `modification_time`, `access_time`, `entry_modification_time`,
POSIX seconds — and the MD5 the L01 stores for the entry, where it stores one. A
getter libewf refuses is recorded against that field (`l01_field_errors`) and
the walk continues.

**Bounds, stated on the record:** at most **1,000,000 entries** and **256 levels**
below the root, walked iteratively (one libewf entry held per level of the
current path). Reaching either sets `entry_cap_reached` / `depth_cap_reached` on
the inventory record, counts the listed entries not walked, and stamps
`content_incomplete` (`cap_reached`) with a sentence saying which ceiling fired.
The parent refuses a walk from the helper that declares more than the million
entries, carries an entry frame over 1 MiB, or has a parent link that does not
point one level up at an earlier entry.

**What it does not do:**
- EnCase stores data against some **directory** entries too. Where a directory's stored data equals its recorded size (on the
  NGDC phone L01s, 123 to 191 per file, among them a 192-byte record beside each
  photo), it is served as the directory's own stream, a second `FileEntry` at
  `<directory>:l01_directory_data`, read through libewf for that directory
  entry, so it is hashed, carved and searched like any file. It is **not
  decoded**: the photo records hold the photo's name, its size as text and four
  32-bit POSIX times, but those times agree with neither the zip export's file
  times nor a constant offset from them (`VALIDATION.md` §L01-1), and no
  published description of the record was found, so nothing in it is presented
  as a time. A directory that records no size and stores one byte (609 to 745
  per file) is in the form libewf reads as an entry with no content; it is
  marked `l01_directory_placeholder_byte` and counted, and that byte is not served.
  The walk reads the byte from the media stream at the
  entry's offset and records it as `l01_directory_placeholder_value` (0-255), or the
  read failure in `l01_field_errors` (a placeholder with no usable media offset is not
  read, and its detail says so). Whether the byte is this entry's alone is checked on
  every L01, not assumed: after a complete walk, each placeholder's byte is compared with
  every walked entry's stored span, and with every sparse entry's read at its duplicate
  data offset (as many bytes as its recorded size), and marked
  `l01_directory_placeholder_byte_span` `alone` or `shared`; the detail says no other
  entry's stored data covers that byte only for `alone`. After an incomplete walk the mark
  is `not_checked_walk_incomplete`, and where any walked entry's span is not known
  (libewf would not give its media offset or size, or a sparse entry's duplicate offset or
  flags, or it stores data at no usable offset; counted in `stored_spans_unknown`) the
  mark is `not_checked_span_unknown`: an unknown span could cover the byte, so no such
  claim is made either way. On the five NGDC files no span is unknown, every placeholder
  is `alone`, and the entries' stored spans tile the media with no gap or overlap. Per the EWF specification a size-0 entry carries one data byte by rule, and libewf
  neither reads nor interprets it; the value is recorded, not served, and carries no
  meaning.
- An entry **flagged sparse** is served as libewf
  20140816's `libewf_file_entry_read_buffer` reads it, established from that
  source: where the entry table names a **duplicate data offset** (`du`), the
  recorded size is read from the media stream at that offset — EnCase stored the
  content once, for another entry with the same bytes — and otherwise the one
  stored byte is repeated to the recorded size. The record says which
  (`l01_content_source`), names the entry whose data sits at the duplicate
  offset (`l01_duplicate_of_path`), and hashes the bytes served (up to 64 MiB)
  against the MD5 the L01 stores for the sparse entry
  (`l01_duplicate_content_check`). A match serves the entry unstamped; a
  mismatch is `unresolved_structure`; no stored MD5, a larger entry, or a read
  failure stays `unvalidated`. On the NGDC files the one sparse entry per file
  names the offset of `http_m.facebook.com_0.localstorage` and its 12,288 served
  bytes match its stored MD5. No real L01 here exercises the one-byte fill.
- Times are projected onto the timeline only where non-zero; the only public
  L01s graded record every time as 0, so the projection is pinned by a unit test,
  not by real evidence.
- **`.Lx01` (EWF2) is not read**: no public sample exists to test against. A
  multi-segment `.L01` set opens through the same glob as an E01 set but has been
  tested on no real one.
- The content resolver re-opens an entry by re-walking the file (in the helper)
  and finding it by `l01_index_path`; up to four entry sources are kept.

Graded in `VALIDATION.md` §L01-1.

**Metadata Extraction** — exactly what is read, and nothing more:
- Case number
- Evidence number
- Description
- Examiner name (published as `examiner`)
- Notes
- Media size, number of sectors, bytes per sector
- The EWF hash section's `MD5` and `SHA1` — the acquisition tool's hashes of
  the **decoded media**, published as `stored_md5` / `stored_sha1`

**Not read, and therefore never on the record:** acquisition date and time,
the imaging software and its version, the acquiring operating system, the drive
serial number and model, the EWF format variant, the compression method and the
chunk count. An examiner asking "when, and with what, was this acquired?" gets
nothing from this module.

**Integration:**
- Transparent DataSource implementation
- Reads go through `libewf_handle_read_random`, so no seek position is kept
- Each read is served from a 64 KiB chunk-aligned, 128 MiB LRU cache
  (2,048 chunks per opened image), because every libewf read re-decompresses
  the whole containing chunk
- **By default libewf runs in a separate `seance-ewf-helper` process**, so a
  segmentation fault inside a C library on hostile evidence kills only the
  child. It falls back to in-process parsing when `SEANCE_E01_ISOLATED` is
  false or the helper binary is absent
- Compatible with all Seance parsers

### Implementation

**Module:** `seance_container_e01`
**Dependencies:** libewf (via FFI), bindgen
**Files:**
- `seance_container_e01/src/lib.rs` - Main module implementation
- `seance_container_e01/build.rs` - Bindgen build script
- `seance_container_e01/wrapper.h` - C header wrapper

### Usage

#### Prerequisites

Install libewf on your system:

```bash
# macOS
brew install libewf

# Ubuntu/Debian
sudo apt-get install libewf-dev

# Fedora/RHEL
sudo dnf install libewf-devel
```

#### Opening an E01 Image

```rust
use seance_container_e01::{E01ContainerModule, E01DataSource};
use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::DataSource,
};
use std::sync::Arc;

// Option 1: Direct DataSource creation
let e01_source = E01DataSource::open("/path/to/evidence.e01")?;
println!("Image size: {} bytes", e01_source.size());

// Read data at any offset
let mut buffer = vec![0u8; 512];
e01_source.read_at(0, &mut buffer)?;

// Option 2: Module-based processing (auto-detects .e01 files)
let module = E01ContainerModule;
let artifact = Artifact::new(
    case_id,
    ArtifactType::Container,
    None,
    json!({
        "name": "evidence.e01",
        "path": "/path/to/evidence.e01",
        "subtype": "e01"  // Auto-populated during ingestion
    })
);

let results = module.process(&artifact)?;
// Results contain RawEvidence artifact with E01DataSource attached
```

#### Metadata Extraction

```rust
let e01_source = E01DataSource::open("/path/to/evidence.e01")?;
let metadata = e01_source.get_metadata()?;

println!("Case Number: {}", metadata["case_number"]);
println!("Examiner: {}", metadata["examiner"]);
println!("Description: {}", metadata["description"]);
println!("Media Size: {} bytes", metadata["media_size"]);
println!("Sectors: {}", metadata["sectors"]);
```

### Output Artifacts

The E01 module produces the following artifacts:

#### RawEvidence Artifact

The E01 module outputs a `RawEvidence` artifact with `subtype="raw"`:

```json
{
  "artifact_type": "RawEvidence",
  "metadata": {
    "name": "evidence.e01_extracted",
    "size": 10737418240,
    "subtype": "raw",
    "container": "e01",
    "container_path": "/cases/case001/evidence.e01",
    "e01_metadata": {
      "case_number": "2024-001",
      "evidence_number": "Evidence-001",
      "description": "Suspect's laptop hard drive",
      "examiner": "J. Smith",
      "notes": "Acquired with FTK Imager",
      "media_size": 10737418240,
      "sectors": 20971520,
      "bytes_per_sector": 512,
      "source_file": "/cases/case001/evidence.e01",
      "stored_md5": "e7d5b36a407d5a02d0872d4dd3f3f9d0",
      "stored_sha1": "5edc4c6efda9d266ecabcab5629694d0063e9d7f",
      "segment_count": 3,
      "segment_files": ["evidence.E01", "evidence.E02", "evidence.E03"],
      "segment_bytes_total": 9663676416
    },
    "stored_md5": "e7d5b36a407d5a02d0872d4dd3f3f9d0",
    "stored_sha1": "5edc4c6efda9d266ecabcab5629694d0063e9d7f"
  },
  "data": "<CachingDataSource over the isolated helper, or over E01DataSource>"
}
```

**Artifact Fields:**
- `name`: `<artifact name>_extracted`, or the opened file's own name where the
  artifact carries none
- `size`: Uncompressed media size in bytes
- `container`: Always "e01"
- `container_path`: Path to E01 file(s)
- `e01_metadata`: The metadata read above, in one object
- `stored_md5`, `stored_sha1`: also written at the **top** level, because that
  is where `evaluate_integrity` reads the baseline it compares a recomputed
  media hash against
- `segment_count`, `segment_files`, `segment_bytes_total`: the composition of
  the set on disk
- `segment_bytes_known`, `segments_unstatable`, `inventory_incomplete`,
  `inventory_incomplete_reason`: where a segment named in the set could not be
  `stat`ed, the total is `null` and the partial sum is published under its own
  name (B7-030). These four are hoisted to the top level, because every
  consumer of the incompleteness pair reads the top level

#### Logical evidence file artifacts

A logical evidence file produces no `RawEvidence`. It produces:

- one `ParsedRecord` with `type: "LogicalEvidenceInventory"`, `subtype:
  "ewf_logical_inventory"`: `entries_published`, `root_present`, `entry_cap`,
  `depth_cap`, `entry_cap_reached`, `depth_cap_reached`, `entries_not_walked`,
  `walk_errors` (first 100) and `walk_error_count`, `unreadable_names`,
  `entries_with_field_errors`, `directory_data_streams_published`,
  `directory_placeholder_bytes_not_served`, `directory_placeholder_values_recorded`,
  `directory_placeholder_spans_checked`, `directory_placeholder_bytes_alone`,
  `directory_placeholder_bytes_in_shared_span`, `stored_spans_unknown`,
  `directories_with_data_not_served`
  (only where a directory's stored data disagrees with its size),
  `walk_incomplete`, `media_size`, `e01_metadata` and `e01_open_mode`, plus the
  `content_incomplete` triple when the walk is incomplete;
- one `FileEntry` per entry, flat under the container, in pre-order: `name`,
  `path` (`/`-joined from the root, e.g. `/LogicalEntries/Raw Data/...`),
  `parent_path`, `size`, `is_directory`, `container: "ewf_logical"`,
  `container_path`, `l01_entry_ordinal`, `l01_index_path` (the entry's identity —
  names need not be unique), `l01_entry_type`, `l01_flags`,
  `l01_media_data_offset`, `l01_media_data_size`,
  `l01_duplicate_media_data_offset`, `l01_sub_entries`; the four times raw as
  `l01_creation_time`, `l01_modification_time`, `l01_access_time`,
  `l01_entry_modification_time` and, where non-zero, as RFC 3339 UTC `created`,
  `modified`, `accessed` and `changed` (entry modification is a metadata change);
  `stored_md5` with `stored_hash_source: "l01_entry"` where the L01 stores one,
  which Verify Integrity uses as the baseline; and a data source for every
  non-directory entry; a sparse entry adds `l01_content_source`,
  `l01_content_source_detail`, `l01_duplicate_content_check` and, where the
  duplicate offset is another entry's, `l01_duplicate_of_path` /
  `l01_duplicate_of_ordinal`;
- after each directory whose stored data equals its size, its stream: a
  `FileEntry` named and pathed `<directory>:l01_directory_data`,
  `is_directory: false`, `l01_record_kind: "directory_data"`,
  `l01_directory_data_of`, the directory's `l01_index_path` and media values,
  `l01_directory_data_decoded: false`, and a data source (the content resolver
  re-opens it as that directory's data, never as a file);
- or, where libewf cannot open or walk the file, one `ContainerRefusal`
  `ParsedRecord` (`subtype: "ewf_logical_evidence"`, `content_incomplete`,
  `unresolved_structure`) giving libewf's reason.

### Technical Details

**Architecture:**
- Uses libewf via Rust FFI (Foreign Function Interface)
- Bindgen generates Rust bindings from libewf.h at build time
- E01DataSource implements the DataSource trait
- Proper Drop implementation for resource cleanup
- `Send + Sync` are asserted by hand: by default the libewf handle is
  not in this process at all, and in the in-process fallback the handle is
  behind a mutex. Neither arrangement has been put through ThreadSanitizer or
  Miri, so this is a reasoned claim and not a measured one

**Performance:**
- Transparent decompression handled by libewf
- Efficient seeking without decompressing entire image
- Minimal memory overhead per read; up to 128 MiB of chunk cache per opened
  image, and the API's content resolver keeps up to eight containers open
- **Demonstrated on one 33 GB set, not on very large ones.** The 21-segment `LoneWolf.E01` set, which was OOM-killed three times on a 30 GB host, ingests completely at a 10.1 GB peak resident set
  (`VALIDATION.md` `INGEST-MEM-1`). That is one image and one run: no claim is made here about
  terabyte images

**Limitations:**
- Requires libewf to be installed on the system
- Write operations not supported (read-only)
- EWF2 (`.Ex01`, `.Lx01`) is not matched by the name gate at all — four
  characters — so an `Ex01` reaches the module only via content detection; an
  `Lx01` is not read (no public sample exists to test the logical walk on it)
- Nothing here checks that a multi-segment set is a contiguous `1..n` run; that
  check lives in the ingest layer, over the files on disk, and governs whether
  an acquisition baseline may be recorded rather than whether the image opens
- No hash is computed or compared here. The recorded baseline is published for
  the integrity path to use later
- Encrypted EnCase images are not supported: no key or password call exists in
  this crate

---

## AFF4 Format (Advanced Forensic Format 4)

### Status: ✅ Production Ready

AFF4 is an open-source alternative to proprietary formats like E01. Seance
reconstructs the logical image behind a `DataSource`, reading and decompressing
chunks on demand, so an AFF4 image ingests like any raw image — no external
conversion required.

### Features

**Current Capabilities:**
- AFF4 file detection (`.aff4` extension)
- ZIP container parsing (AFF4 uses ZIP as its container)
- Turtle (RDF) metadata parsing of `information.turtle` (image / ImageStream / map URNs)
- Bevvy index parsing (`<urn>/<bevy:08d>.index`) for per-chunk addressing
- On-demand chunk read + decompression (snappy or deflate; incompressible
  chunks stored raw)
- Striped images spread across multiple `.aff4` files in the same directory
- Symbolic streams: a range mapped to `#zero` or any `aff4:SymbolicStream<HH>`
  is served as that constant byte. **Unreadable and unknown data are not**:
  `aff4:UnreadableData` is served as the repeating marker `UNREADABLEDATA` and
  `aff4:UnknownData` as `UNKNOWNDATA`, both counted on the artifact's coverage
  keys (B4-017), because a zero-filled bad sector is byte-for-byte a sector
  that held zeroes
- **A hash predicate on the image or stream subject is read, where the graph
  carries one.** `aff4:md5`/`aff4:sha1`/`aff4:sha256` and the generic
  `aff4:hash` (whose algorithm is read from its `^^datatype` suffix) are all
  matched case-insensitively; an MD5 or SHA-1 found is published as
  `stored_md5`/`stored_sha1` at the artifact's top level, exactly like the E01
  reader, so the decoded-media verification pass runs for an AFF4 exhibit
  that records one. A SHA-256 found is published under `aff4_hash_sha256`,
  because that verification pass still checks only `stored_md5`. **No
  predicate spelling here is pinned by an authoritative AFF4 specification in
  this tree** — none is vendored — so this is the plausible set, not a
  certainty; a real AFF4 corpus (c-aff4, pyaff4, Evimetry) should be checked
  against it. Where the graph carries no recognised hash predicate at all,
  `aff4_hash_baseline: "not recorded in container"` says so explicitly

**Module ID:** `container.aff4_reader` — emits a `RawEvidence` artifact backed by
an `Aff4DataSource`, exactly like the E01 reader.

### Implementation

**Module:** `seance_container_aff4`
**Key types:** `Aff4ContainerModule`, `Aff4DataSource` (implements `DataSource`)
**Files:**
- `seance_container_aff4/src/lib.rs` - Reader implementation

### Usage

AFF4 images are ingested exactly like any other container — point ingestion at
the `.aff4` file and the module attaches an `Aff4DataSource`:

```rust
use seance_container_aff4::{Aff4ContainerModule, Aff4DataSource};
use seance_core::data_source::DataSource;

// Direct DataSource creation (reconstructs the logical image on demand)
let source = Aff4DataSource::open("/path/to/evidence.aff4")?;
println!("Image size: {} bytes", source.size());
let mut buffer = vec![0u8; 512];
source.read_at(0, &mut buffer)?;

// Or module-based processing (auto-detects .aff4 files)
let module = Aff4ContainerModule;
let results = module.process(&artifact)?;
// Results contain a RawEvidence artifact with an Aff4DataSource attached
```

### Output Artifacts

The AFF4 module produces a `RawEvidence` artifact (`subtype="raw"`) backed by an
`Aff4DataSource`, matching the E01 reader's output. Downstream partition and
filesystem parsers consume it transparently.

**Notes / limitations:**
- ZIP is the on-disk container; the turtle graph, bevvy index, and chunk
  streams are parsed from inside it.
- Compression: snappy and deflate are supported. LZ4 chunk streams are not yet
  handled.
- Hash verification of the reconstructed stream is not yet performed.

---

## Virtual Disk Images (VHD / VHDX / VMDK / QCOW2)

### Status: ✅ Production Ready

Virtual machine disk images are opened as `RawEvidence` sources, so their guest
partitions and filesystems are analysed like any physical image.

**Module:** `seance_container_vdisk`
**Module IDs:** `container.vhd_reader`, `container.vhdx_reader`,
`container.vmdk_reader`, `container.qcow2_reader`
**Files:** `seance_container_vdisk/src/{vhd,vhdx,vmdk,qcow2}.rs`

Each reader implements a `DataSource` over the virtual disk (fixed and dynamic
VHD, the VHDX block allocation table, monolithic sparse VMDK, and QCOW2 L1/L2
cluster tables) and emits a `RawEvidence` artifact.

**Notes and limitations.** These are refusals the readers make on purpose, and
each is pinned by a test:

- **Differencing disks are refused, in both readers.** A VHD of disk type 4
  ("its parent is required and not available") and a VHDX with a parent
  ("differencing disk (parent-backed) not reconstructed") produce nothing. A
  Hyper-V checkpoint set — the ordinary `.avhdx` case — is therefore refused,
  not read.
- **A QCOW2 with a backing file is refused** ("backing file unsupported"),
  because serving the holes as zeroes would fabricate content the base image
  holds. Compressed clusters are likewise not read.
- **VMDK: monolithic sparse only.** streamOptimized is refused three ways
  (flag bit 16, a non-zero `compressAlgorithm`, the footer-GD sentinel), and
  **no descriptor is parsed anywhere** — `descriptorOffset` and
  `descriptorSize` are never read, so flat extents, descriptor-led extent
  lists and split sets produce nothing, and a snapshot delta is not
  distinguishable from a base disk.
- No reader replays a VHDX log or verifies a checksum, and none of them
  reconciles a declared capacity against the allocation it can actually see.
- Each reader's bounds: the VHDX region table is walked for at most 2,047
  entries, its metadata region is capped at 16 MiB, and the VMDK grain
  directory at 4 MiB (1,048,576 entries).

A refused disk leaves the reason in the case's processing log. None of these
four readers emits a refusal record of its own, so on the artifact tree a
virtual disk that would not open is not distinguishable from one nobody
pointed at.

---

## Archive & Compressed-Stream Expanders

### Status: ✅ Production Ready

Single-stream compressed containers and compound files are transparently
expanded so their payloads re-enter the pipeline.

**Module:** `seance_container_archive`
**Module IDs:** `container.gzip_expander`, `container.bzip2_expander`,
`container.xz_expander`, `container.7z_expander`, `container.tar_extractor`,
`container.ole2_expander`
**Files:** `seance_container_archive/src/{gzip,bzip2,xz,sevenz,tar_archive,ole2}.rs`

- **gzip / bzip2** — decompress **every member** of a file (a gzip file and a
  bzip2 file may each be a series of complete members laid end to end) to one
  contained payload.
- **xz** — decompress a single stream to its contained payload.
- **7z** — list member entries from a 7-Zip archive (names and sizes; entry
  content is not extracted).
- **tar** — expand a tar archive's members (`TarExpanderModule`, registered in
  `seance_api::modules` alongside the others; `extract_tar_entry_source` opens a
  single member).
- **OLE2** — walk the Compound File Binary (CFB) directory of legacy Office /
  MSI / other OLE2 documents.

All of them run under the decompression ceiling described below.

**Multi-member gzip and bzip2.** After each member
the expander reads the next bytes and decodes another member only where the
format's magic (`1F 8B`, `BZh`) begins one, so a `cat a.gz b.gz`, a rotated log
appended in place or a multi-stream `.bz2` expands in full, as `zcat` / `bzcat`
print it. The child carries `compressed_members`. Bytes after the last member
that do not begin another are **not decoded** but are recorded:
`trailing_bytes_after_last_member`, `trailing_bytes_offset` and
`trailing_bytes_all_zero`; when they are not all zero the child is also marked
`content_incomplete` (`unresolved_structure`), because they may be a damaged
member. Zero padding is counted and not called a gap. A member that begins
with the magic and then fails to decode still fails the whole expansion closed
(the members before it are not served), and member boundaries inside the child
are not recorded. The xz expander is unchanged: `xz2`'s `XzDecoder::new` is
single-stream, and a concatenated `.xz` is **not expanded at all** and is
recorded as `xz_decompress_failed` — a recorded refusal rather than a silent
partial.

**Tar walk.** A member's size is `Entry::size()`,
which honours a PAX `size` record, so a member over 8 GiB (whose ustar size
field Python's `tarfile` and GNU tar's posix format zero) is published at its
real size and windowed to the bytes present. A walk that reaches end-of-file on
a header boundary with no all-zero end-of-archive block produces an
`ArchiveScanStatus` with reason `tar_end_marker_missing` — GNU tar lists such a
cut copy without complaint. A PAX global header (`g`, the `pax_global_header`
`git archive` writes) is skipped rather than listed, and its attributes are not
recorded. Symbolic and hard links are published as links: `is_symlink` /
`symlink_target` or `is_hardlink` / `hardlink_target`, `tar_entry_type`, and no
data source. Still not handled: devices and FIFOs are listed as files.

**Sparse members.** A sparse member is served at its real
size from its own map: each stored region at its offset, each hole as zeros
(`tar_sparse`, `sparse_regions`, `sparse_stored_bytes`). Both GNU forms are read —
the old GNU type `S` header (map in the header and its extension blocks, which
tar-rs validates but does not publish, and whose data it mis-locates) and the
POSIX `GNU.sparse.*` PAX forms 0.0, 0.1 and 1.0, whose real name and size come
from the PAX keys. A cut archive serves the file up to the first stored byte it
does not hold and flags `short_read`; a map that will not read gives the member no
data source and an `unresolved_structure` reason. Graded on GNU tar 1.35 output in
all four forms and on dfir_ntfs's `vss_2_stor.tar.gz` (5 GiB, 58 stored regions).

**After the end marker.** When the walk ends on the
end-of-archive block, the bytes after it are read. Zeros (the second end block
and GNU tar's record padding) are not reported; anything else produces an
`ArchiveScanStatus` with reason `tar_bytes_after_end_marker`, the byte count,
where they start, the first non-zero offset and, when a ustar header begins
there, `trailing_tar_header_at` — a second archive appended with `cat`. Its
members are recorded as present but are **not listed**; GNU tar lists them only
with `--ignore-zeros`.

**Encrypted 7z.** A 7z whose header is encrypted
(`7z a -p… -mhe=on`) is recorded with reason **`encrypted`** (both
incompleteness pairs, `encrypted_header: true`, `scheme: 7z_aes256_sha256`),
so it reaches the Needs-attention queue. An entry in an AES-encrypted
folder of an archive whose header is plain (`7z a -p…`, the default) carries
`encrypted: true` and reason `encrypted` in place of `compressed`. Any other
failure to open is still `sevenz_unreadable`.

**A 7z password for one archive.** The
header-encrypted archive's queue row takes its password (`kind:
sevenz_password` on the credential route). With it the archive is listed again:
its entries' names and sizes appear beneath it — still `content_incomplete`,
reason `compressed`, `encrypted: true`, `password_supplied: true`, because this
build extracts no 7z content at all — and an `ArchiveScanStatus` of `status:
unlocked` supersedes the "encrypted, not expanded" record. For an archive whose
header is plain the entries are not listed a second time: the password is
checked by decoding the first encrypted entry against its CRC-32 (the first
mebibyte only, reported as `password_check: decoder_prefix`, when that entry is
over 64 MiB), and an `ArchiveScanStatus` of `status: password_verified` says so.
Those entries' queue row offers **no** field — a password would not bring 7z
content into the case — and says how to check one. A wrong password is rejected
and records nothing. Pinned on real `7z a -p… [-mhe=on]` output
(`seance_container_archive/tests/fixtures/password_*.7z`).

---

## ZIP Format

### Status: ✅ Production Ready

Standard ZIP archive extraction for containerized evidence.

**Module:** `seance_container_zip`
**Capabilities:**
- ZIP file detection
- Member file extraction
- Metadata extraction (name, size, compression)
- FileEntry artifact generation
- **Expansion by extension covers thirteen names**, not seven: `zip`, `docx`,
  `docm`, `xlsx`, `xlsm`, `pptx`, `pptm`, `jar`, `odt`, `ods`, `odp`, `apk`
  and `ufdr` (Cellebrite mobile extraction)
- **Decompression:** stored, deflate, bzip2 and zstd (the `zip` crate's
  default feature set)
- **Encrypted entries are surfaced, not skipped**: an `EncryptedArchive`
  record names them, and `crack-zip` will attempt a wordlist or mask against
  ZipCrypto and WinZip AES without weakening either check
- **Path traversal is resolved and recorded**: an entry whose name escapes the
  archive root is published under a safe name with `path_traversal` and
  `original_name` on the record
- DOS timestamps are local-time with no zone in the format, and carry
  `timezone: "local"` saying so
- **Ceilings:** 4 GiB per entry, and a partial read leaves an
  `ArchiveScanStatus` record stating what was not expanded

**See:** `seance_container_zip/src/lib.rs`, and the method statement for
`container.zip_extractor` in `documentation/METHOD_STATEMENTS.md`.

---

## RAW Format

### Status: ✅ Production Ready

Direct disk image access without container format.

**Module:** `seance_core::data_source::FileDataSource`
**Capabilities:**
- Direct file access
- Memory-mapped I/O where beneficial
- Seek + Read at any offset
- No compression or metadata

**Usage:**
```rust
use seance_core::data_source::FileDataSource;

let raw_source = FileDataSource::new("/path/to/disk.raw")?;
```

---

## Optical disc images (ISO 9660 and UDF)

### Status: ⚠️ ISO 9660 read; UDF read on every partition kind to 2.50, graded on real evidence only for 1.02

An `.iso` (or any raw volume) is handed to the partition layer, which probes
for both disc filesystems. ISO 9660 is recognised by `CD001` at byte 32,769. UDF
is recognised by its Volume Recognition Sequence: 2,048-byte descriptors from
byte 32,768, where a `BEA01` must be followed by `NSR02` or `NSR03` before the
`TEA01` that closes the extended area. An `NSR` outside a `BEA01`/`TEA01` pair is
not believed. When the 2,048-byte slot after the first descriptor is blank, the
sequence is also walked in 4,096-byte steps, so a 4 KiB-sector UDF volume is
recognised rather than read as no filesystem.

**The UDF bridge.** A disc carrying both (every Windows install ISO, most
authored DVDs) gets two `FileSystem` artifacts, `iso9660` and `udf`, each stamped
`udf_bridge: true`. Neither is marked `hidden` or given an `overlap_warning`:
two directory trees describing the same files is how the format is designed,
not one filesystem hiding another. A third signature found beside the pair
still raises the overlap warning. The two halves may differ, and nothing
compares them: two halves that list different files raise no signal. On the
Windows 11 25H2 ISO the ISO 9660 half holds only `README.TXT`, and all 976 files
are in the UDF half (`UDF-BRIDGE-1` in `VALIDATION.md`).

Both halves are also pinned in every build by a small committed hybrid
(`seance_plugin_udf/tests/fixtures/hybrid_iso9660_udf250.img.gz`): the partition layer
yields `iso9660` then `udf`, the ISO reader lists its one file (`ISO_ONLY.TXT`, absent
from the UDF tree) byte-exact, and the UDF reader lists the whole payload with the
answer key's hashes and not the ISO-only file. **That image is spliced, not authored**:
a hand-written ISO 9660 half in the free sectors of a `makefs` UDF 2.50 volume,
cross-checked by `xorriso` (ISO half) and `7z` (UDF half). It pins the mechanism; the
real authored hybrid is the Windows ISO above.

**UDF depth (`seance_plugin_udf`).**

| | Read | Refused, and named |
|---|---|---|
| Anchor | Sector 256, then N-1, then N-257, in 2,048-byte sectors, then in 512-, 1,024- and 4,096-byte sectors; the size the anchor is found at is the size every descriptor is read in (`sector_size` on the volume record). A 512- or 1,024-byte-sector volume (Windows `format /fs:UDF` on a USB disk, say) still carries its recognition sequence in 2,048-byte steps, so the partition layer writes the `udf` subtype and the anchor tells the size | A Logical Volume Descriptor whose block size differs from the sector size the anchor was found at. No 1,024-byte-sector volume has been read |
| Descriptors | Tag checksum and CRC-ITU verified on every descriptor. The main Volume Descriptor Sequence is read, with the reserve as the fallback | A descriptor that fails its checks fails its whole sequence |
| Partition maps | Type 1 (physical). `*UDF Sparable Partition` (CD-RW/DVD-RW): the verified sparing table with the highest sequence number relocates packets. `*UDF Virtual Partition` (CD-R/DVD-R/BD-R): the Virtual Allocation Table, UDF 1.50 or 2.00+ form, found in the last recorded block (trailing zeros skipped, up to 64 MiB). `*UDF Metadata Partition` (UDF 2.50+): the metadata file, or its mirror when the main copy will not read. The volume record names each map in `partition_map_kinds` | A Type 2 map of another kind (`udf_unsupported_partition_map`). A known kind whose structures will not read — no VAT found, no sparing table verified, neither metadata file readable — stamps `udf_partition_map_unresolved` with the reason. Either way no files are listed |
| File entries | File Entry and Extended File Entry, ICB strategy 4 | Other strategies (`icb_strategy_unsupported`) |
| Allocation | Short, long and embedded descriptors, and Allocation Extent Descriptor chains. Unrecorded extents read as zeros | Extended allocation descriptors. Allocation (extents or embedded bytes) shorter than the information length is flagged `content_incomplete`, `udf_content_problem: allocation_shorter_than_information_length`: the zero tail is not on the disc |
| Names | OSTA CS0, compression 8 and 16 | Other compression ids: the name is published as hex with `name_decode_failed` |
| Content past the evidence | — | An extent inside its partition but past the end of the image (a truncated acquisition, an ISO cut at 4 GiB) is served as far as the image goes and flagged `content_incomplete` (`short_read`), `udf_content_problem: extent_past_end_of_evidence`; the volume record carries `partition_extends_past_evidence` |
| Not read, flagged | — | Extended attributes and named streams (flagged on the entry), symlink targets |
| Multisession | On a VAT volume, the newest VAT, which describes the last session, when the image holds every session in order. Earlier VATs are located and counted (`vat_earlier_icb_lbns`, `vat_earlier_states_not_walked`) | The volume as it stood under an earlier VAT is not walked, so a file removed in a later session is not listed. An image cut before its last session is read as the earlier state its last VAT describes, with nothing to mark it. A multisession disc not joined by a VAT is read only as the session the anchor names; other sessions are **not detected**: an image file carries no session table |

File content is served from its extents. Nothing is read into memory, so a
6 GB `install.wim` is served whole. A deleted File Identifier is listed with
`deleted: true` and `deleted_icb_may_be_reused: true`, and its directory is not
walked. One whose ICB extent is zeroed (as the Linux driver leaves it) carries
`icb_unreadable_reason: icb_not_recorded`. A timestamp that is recorded but out
of range is not published and is named in `timestamps_undecodable`. On a VAT
volume the partition spans the whole disc and nothing after the VAT was written,
so the volume record says `partition_unrecorded_after_vat` rather than
`partition_extends_past_evidence`.

The one real disc graded is UDF 1.02 (`UDF-BRIDGE-1`). Virtual, sparable and
metadata partitions, UDF 1.50, 2.01 and 2.50, and 512- and 4,096-byte sectors are
graded on **self-made** volumes written by NetBSD `makefs` and `mkudffs` 2.3 from a
synthetic payload, byte-exact against the payload (`UDF-VARIANTS-1`); no real burned,
rewritable or Blu-ray disc has been held. A relocated sparing packet, an unreadable
main metadata file and an earlier VAT are pinned only by editing a copy of one of
those images.

## Apple Sparse Disk Image (`.sparseimage`)

### Status: ✅ Reader shipped

`.sparseimage` is what the mainstream Mac acquisition tools (FUJI, RECON, ASLA)
write: a file that starts empty and grows one *band* at a time, so the file on
disk is far smaller than the disk it represents.

**Module:** `seance_container_sparseimage`
**Module ID:** `container.sparseimage_reader`
**Subscribes to:** `Container` **and** `FileEntry` — so a `.sparseimage` found
*inside* another filesystem is opened as well as one handed to ingest directly.

The reader decodes the fixed 4096-byte header (signature `sprs`, sectors per
band, total 512-byte sectors, and the band index array at `0x40`) and presents
the contained disk as an ordinary `DataSource`, so the existing partition,
filesystem and carving stack runs on it unchanged. The layout was verified
against libyal/libmodi's `libmodi_sparse_image_header.c`.

**Two bounds, both deliberate:**

- The band array cannot exceed `(4096 - 0x40) / 4 = 1008` entries, because
  libmodi reads only the 4096-byte header. A larger count is **rejected**, not
  trusted.
- A logical band with no index entry was never written and reads as zeros —
  that is the sparseness. A band that *is* mapped but whose bytes are missing
  from a truncated file is an **error**, never silent zeros: a truncated
  capture must not read as a sparse one.

---

## Network captures (pcap / pcapng)

### Status: ✅ Stages 1 and 2 shipped

A packet capture is not a disk image, but it is a container of evidence and
this document owns the question it raises: which formats open, to what depth,
and what the record says when the answer is "not all of it".

**Module:** `seance_plugin_pcap`
**Module ID:** `plugin.network.pcap_parser`
**Subscribes to:** `RawEvidence` **and** `FileEntry` — a capture handed to
ingest directly, or one found inside a filesystem, is read the same way.
**Detection:** by content only (`seance_core::file_detection`). Case 001's
capture is named `.pcap` and is a pcapng; a capture carved out of unallocated
space has no name at all.

### Container formats

| Format | Magic | Read |
|---|---|---|
| Classic pcap, microsecond | `A1B2C3D4` in either byte order | ✅ version 2.4. Detection is by the magic alone; the reader refuses any other version with a `NetworkCaptureRefusal` naming the number it read, so a 2.5 header (or 2.4 written in the byte order the magic does not announce) leaves a record under the source rather than nothing |
| Classic pcap, nanosecond | `A1B23C4D` in either byte order | ✅ the fraction is scaled to microseconds |
| pcapng 1.x | `0A0D0D0A` block type **and** `1A2B3C4D` byte-order magic at offset 8 | ✅ multi-section; each section's byte order is read from its own SHB |

pcapng blocks read: **SHB** (with `shb_hardware`, `shb_os`, `shb_userappl`,
one provenance entry per section), **IDB** (linktype, snaplen, `if_name`,
`if_tsresol`), **EPB**, **SPB** (no timestamp — the packet is emitted with
none, never with the epoch), **ISB** (`isb_ifrecv`, `isb_ifdrop`,
`isb_osdrop`; the last value per interface, since the counters are cumulative).
Every other block type — including the Name Resolution Block (4) and the
Decryption Secrets Block (10), which each carry evidence — is **counted by type
code and not read**, and the count is on the capture record.

Timestamps are resolved per interface through `if_tsresol`, both the 10^-n and
the 2^-n forms. A resolution no 64-bit count can date a real capture at, or a
scaled instant that overflows, yields **no timestamp**, counted under
`packets_with_unresolvable_timestamp`; nothing is ever dated 1970 for want of
a better answer.

### Link, network, transport, application

| Layer | Decoded | Everything else |
|---|---|---|
| Link | LINKTYPE **1** Ethernet II (up to three stacked 802.1Q / QinQ tags), **101** RAW IP, **113** Linux SLL | Any other linktype: a `NetworkCaptureRefusal` record per interface **naming the number**, and every packet on it counted under `unsupported_linktype`. Never an empty flow list. |
| Network | IPv4 with the header checksum **verified**; IPv6 with up to eight chained extension headers | A frame with no network layer (ARP, STP, LLDP) is counted as such, not refused. A non-initial fragment carries no transport header and is counted on its IP pair, never given ports from payload bytes. |
| Transport | TCP (ports, flags), UDP (ports) | ICMP, ICMPv6 and every other IP protocol become a flow with no ports, labelled `icmp`, `icmpv6` or `ip-<n>`. |
| Application | DNS on **UDP port 53 only**: query and response, questions, answers with A / AAAA / NS / CNAME / PTR data decoded and other RDATA shown as hex. **HTTP/1.x** and the **TLS handshake**, read out of the reassembled TCP streams **by their own start bytes on any port** (stage 2, below). **ARP** claims. | No HTTP/2 or HTTP/3, nothing inside TLS beyond the handshake, no CONNECT tunnel contents, no QUIC, no SMB, no mDNS (5353), no DNS over TCP. Protocol is decided by the bytes and never by the port: a flow on 443 carrying a binary protocol is **not** reported as TLS, and one on 8080 carrying TLS **is**. |

Two consequences of the checksum rule that an examiner reading a flow list
must know:

- An IPv4 header whose checksum **fails** is refused with its addresses
  (`ipv4_checksum_failed`), counted on the flow for its IP pair with no ports,
  and stamped there. The bytes are in the case; the transport claim is not
  made from a header that did not verify.
- An IPv4 header whose checksum field is **zero** is not refused. On a capture
  taken **on the sending host** with transmit checksum offload, that is every
  outbound IPv4 packet, and refusing them would delete one direction of every
  conversation. The header is intact, the packet decodes with its ports, and
  the flow counts it under `checksum_unset_packets` — a qualification the
  examiner can read, never a stamp. "Not computed" and "corrupt" are different
  findings, and only the second is a refusal.

### Stage 2: what the conversations said

Stage 1 reached the *address* a machine was talking to;
this is what it was **saying**.

**TCP reassembly** (`seance_plugin_pcap::reassemble`). One stream per direction
of each conversation, keyed the way the flow table keys it. The stream is a
list of runs at their true offsets, never one buffer: **a gap is never filled
and never closed**, and only `contiguous_prefix()` — the bytes before the first
missing byte — is offered to any parser. Where two segments claim the same
offsets with **different** bytes the first are held, the conflict is counted
with its offset, and the disagreement is reported rather than resolved: that is
the mechanism behind a family of intrusion-detection evasions. Ceilings, each
reported on the records it bounds: 64 MiB per stream, 4,096 runs per stream,
262,144 streams per capture, and a **256 MiB budget across every stream** (a
per-stream ceiling is no bound on thousands of them). On DFIR Madness Case 001 an RDP brute force would fill a 4,096-stream table
at 02:19:27, about four and a half minutes before the implant was downloaded at
02:24:06 (`VALIDATION.md` NET-4). A conversation the
table has no room for is named on its own `NetworkFlow` record
(`tcp_streams_not_read`, stamped `cap_reached`), because without that its record
read exactly like a flow that carried no bytes. The refusal is per direction:
`tcp_directions_not_read` lists the directions refused, and where the table
filled between a conversation's two directions the stamp names the unread one
and says the other was read — that other stream's request or ClientHello has
its own record.

| Read | Records | What it will not say |
|---|---|---|
| **HTTP/1.x** by start line, on any port | `HttpTransaction` per request-and-response pair: method, the target as sent, the reconstructed URL, every header, the **decoded form fields** of a URL-encoded body and of the query string, the status, and the basis the pairing rests on. Each non-empty body is handed on as its own `FileEntry` artifact — **inflated** where `Content-Encoding` was gzip or deflate — so YARA, the hasher, the file-type detector and the search index see it. **Not the carver**: `seance_plugin_carver` subscribes to file systems and unallocated space only, so a body is never carved, and the modules that do reach it are the ones that take a `FileEntry`. | No HTTP/2 and no HTTP/3 — but HTTP/2's connection preface **is** recognised and counted (`http2_conversations_not_read` on the capture record, with an inventory shortfall), because HTTP/2 is most of the web and a capture full of it would otherwise produce no HTTP records and nothing saying why. A response is paired to a request **by order**, which is how HTTP/1.1 answers on one connection; a pairing over a stream with a gap, or over a conversation whose start the capture does not hold, is marked as one that **may be wrong**. A 1xx, 204 or 304 response, a response to HEAD, and a 2xx response to `CONNECT` are framed as bodyless whatever their headers say — the last of those because what follows it is the tunnel, not the response's content. Two disagreeing `Content-Length` headers are reported as a **disagreement** and no body is claimed — that is a request-smuggling signature, not a framing to choose between. A body in a coding this build does not decode — **`br` and `zstd`, which most current servers prefer** — is kept as the bytes that crossed the wire, stamped `compressed`, and is **not the object**: the search index and the detectors see the compressed stream, not the page. Ceilings, each named on the capture record: 8 KiB per header line, 64 KiB per header block, 256 headers, 256 messages per stream, 8 MiB of body per message on the wire, 32 MiB inflated, 256 MiB of bodies per capture, 10,000 transactions per capture. |
| **TLS** record layer and handshake | `TlsSession` per conversation: the `server_name` the client asked for, the versions offered and negotiated, the cipher (with the known-broken ones flagged from an enumerated list), ALPN, and the client's **JA3** fingerprint with GREASE removed. `TlsCertificate` per certificate a server sent in the clear: subject, issuer, serial, validity window, every alternative name by kind, the key algorithm and size, the extensions by OID, and the SHA-256. A timeline event marks each end of the validity window. | **TLS is recognised only where a stream's first byte begins a handshake record**: TLS behind a protocol preamble — RDP's X.224 connection request, a STARTTLS exchange — gets no `TlsSession`, and neither does a later connection on a five-tuple reused within the capture whose first connection did not open with TLS (`VALIDATION.md` NET-4: four of 15,360 ClientHello-bearing conversations on Case 001, one of them the post-compromise RDP from the domain controller to the desktop). Nothing after the cipher changes is parsed — it is counted. **From TLS 1.3 the certificate is encrypted and no capture can hold it**: a session with none says which of **three** reasons applies — encrypted by TLS 1.3, absent from a cleartext that should have held it, or no `ServerHello` in the cleartext at all so the version is not even known — rather than showing an empty chain. No signature is verified, no chain is built, no trust store is consulted and no revocation is checked; `self_signed` is a statement that two names are identical. A name list cut by the 256-name ceiling will not answer "this certificate does not cover that name". Ceilings: 4,096 records per direction, 256 KiB of cleartext handshake, 16 certificates per chain, 64 KiB per certificate, 131,072 session records per capture — one per conversation the stream table holds. |
| **ARP** (Ethernet/IPv4, on Ethernet and on Linux cooked captures) | `ArpBinding` per address, listing every hardware address that claimed it with first and last seen, the request/reply split, gratuitous announcements in **both** RFC 5227 forms, and any disagreement between a claim and the frame that carried it. A contested address gets a timeline event at the moment the second claimant appeared. | **ARP does not authenticate**: every binding is an announcement that was believed because it arrived. A contested address is reported as contested and **no verdict is reached** — it is equally the signature of cache poisoning and of a failover pair, a DHCP lease handed on, a replaced network card or a host moved between hypervisors. A probe from `0.0.0.0` claims nothing and is not a binding. An ARP frame of another hardware or protocol type is counted as one this build does not read, not as an absence of ARP. Ceilings: 4,096 addresses, 16 claimants per address. |

**Header values are copied onto the record, including `Cookie` and
`Authorization`.** That is a decision, and the alternative — citing them by
capture offset only — is equally defensible, so it is recorded here rather than
left to be inferred: an examiner who does not find a credential on an
`HttpTransaction` record can conclude it was not in the message. The reasoning
is that the examiner already holds the capture, a session cookie is frequently
the only evidence tying an account to a machine, and a record that silently
omitted it would make the search index answer "not present" to a question it
had never asked. Bodies are handed on as artifacts and are therefore hashed and
searched like any other file.

### Records

Named by `metadata.type`. **Most** are `ParsedRecord` artifacts parented to
the capture; three things are not, and where a record sits is part of what it
says:

* a `TlsCertificate` is parented to **its session**, so the chain of custody
  reads capture → conversation → what the server presented on it;
* an HTTP message body is an `ArtifactType::FileEntry` parented to **its
  transaction**, because it is a file and the modules that read a file on disk
  read it;
* there are **three** kinds of `TimelineEvent`, not one — the flow's
  first-seen, two per certificate (`certificate_validity`, at each end of the
  validity window) and one per contested ARP address
  (`arp_address_contested`, at the moment the second claimant appeared). The
  flow event carries `timestamp_micros`; the certificate events carry the
  X.509 string as their timestamp and **no** `timestamp_micros`, because a
  certificate's validity window is stated to the second and inventing
  microseconds for it would be a precision the evidence does not have.

| `type` | One per | What it carries |
|---|---|---|
| `NetworkCapture` | capture | format, version, byte order, interfaces (linktype, snaplen, resolution), the per-section provenance list, packet counts by fate (in flows / refused by reason / no network layer / past the flow cap / on an undeclared interface / short block), first and last seen, ISB drop counters per interface and in total, unknown block types, and the walk's health (`stopped`, `bytes_read`, `over_claimed_packets`, `mismatched_block_trailers`, `truncated_options`) |
| `NetworkFlow` | bidirectional conversation | `protocol`, `local_*` / `remote_*` endpoints, `remote_is_external`, `local_chosen_by` (`internal` or `first_packet`), `local_is_initiator`, packets and bytes each way and in total, `wire_bytes`, first / last seen, `duration_seconds`, `packets_without_timestamp` and `timestamped_packets`, `tcp_state`, `truncated_packets`, `checksum_unset_packets`, `unattributed_packets` by reason, and `refused_packets_between_hosts` (by reason too): packets between the same two hosts refused before a port could be read, which may be this conversation's other half |
| `DnsResolution` | question in a DNS message | the name, `is_response`, `rcode` and `rcode_name` (`NOERROR`, `NXDOMAIN`, …, or `RCODE<n>`), `resolved` (a response with `NOERROR` and at least one answer record read), the answers with RR type names, client and server endpoints, timestamp, `tc` (the server cut the answer set) and `truncated` (the capture cut the message) — kept apart because they are different facts. `resolved_by` is always `capture`: no name is ever looked up from the examination host, and no address is ever geolocated. |
| `NetworkCaptureRefusal` | undecodable interface, or a capture that was detected and then could not be read | the linktype (stamped `content_incomplete` only: the packets on that interface are known to exist and were not decoded) or the reader's error (stamped with both `content_incomplete` and `inventory_incomplete`: nothing past the header is known) |
| `HttpTransaction` | request-and-response pair | the method and the target as sent, the reconstructed `url`, the `host`, every header, the **decoded** `form_fields` and `query_fields`, the status and reason, each message's framing (`body_end`) and whether it is whole, the `body_artifact_id` of each side's body where there is one, the `pairing` and the sentence it rests on, and the facts of both streams (`request_stream` / `response_stream`: gaps, bytes beyond the first gap, conflicts, the reassembler's stop, whether the handshake was captured) |
| `TlsSession` | conversation that spoke TLS | the `server_name` the client asked for and `client_hello_read` (so an absent name is never read as "the client sent none" when the client's half was not captured), the versions offered and negotiated, the cipher and whether it is known-weak, ALPN, `ja3` and `ja3_md5`, the certificate summary, `certificates_unavailable` with its sentence, and both directions' handshake and stream facts |
| `TlsCertificate` | certificate in a cleartext chain | version, serial, signature algorithm, the full subject and issuer plus their CN and O, the validity window, the key algorithm and size, every alternative name **by kind**, the extensions by OID with `critical`, `self_signed`, `covers_the_name_requested` (or `null` where the name list was cut), the SHA-256, and `signature_verified` / `chain_built` / `revocation_checked` — all three stated as `false` rather than omitted |
| `ArpBinding` | address claimed, plus one per signature-without-a-profile | the address, every hardware address that claimed it with first and last seen, the request/reply split, gratuitous announcements, frame-source disagreements, `contested` and `contested_from` |
| `TimelineEvent` | flow with a first-seen; each end of a certificate's validity; each contested ARP address | `timestamp`, `timestamp_desc`, `event_type` where it has one, `source_module` = `plugin.network.pcap_parser`. The flow event's timestamp is RFC 3339 with microseconds and an explicit `+00:00` (so the timeline store keeps sub-second order and offset provenance) plus `timestamp_micros`; the certificate events carry the X.509 time and no `timestamp_micros` |

**`local` and `remote`:** the internal endpoint (RFC 1918, loopback, link-local,
`::1`, `fe80::/10`, `fc00::/7`) when exactly one endpoint is internal;
otherwise whichever endpoint sent the first packet the capture holds.
`remote_is_external` is true only for a routable address — multicast,
broadcast and the unspecified address are not "external", or the top of the
list would be mDNS and DHCP.

**`bytes` is captured bytes**, what the evidence holds; `wire_bytes` is what
the capture engine said crossed the wire. The viewer shows the first and marks
the row only when `truncated_packets` is greater than zero — a packet whose
captured length is short of its wire length. A record whose captured length
*exceeds* its declared wire length makes `bytes` and `wire_bytes` differ with
`truncated_packets` still zero; neither the emitter nor the viewer flags that
case, and the two counts are on the record for the examiner to compare.

**`duration_seconds`** is over the packets that carried a timestamp, and is
`null` for a flow with fewer than two of them: one packet has no duration,
and `0.0` would present it as a measured instant. A flow with some untimed
packets is stamped `content_incomplete` (`unresolved_structure`) saying how
many of its packets `first_seen`, `last_seen` and the duration are over.

**`tcp_state`** is a statement about the flags in the capture, not about the
connection, and every `_no_handshake_seen` token says the opening of the
conversation is not in this file:

| Token | Flags seen |
|---|---|
| `syn_only` | SYN, and no SYN-ACK and no ACK: an attempt that was never answered |
| `handshake_seen` | SYN and SYN-ACK both, and no FIN or RST |
| `handshake_partially_seen` | one half of the opening — the SYN or the SYN-ACK — is in the file and packets flowed after it |
| `established_no_handshake_seen` | packets flowed with flags read, and none of the handshake is in the file |
| `closed` | a FIN, no RST, and a SYN or SYN-ACK was seen |
| `closed_no_handshake_seen` | a FIN, no RST, and no SYN or SYN-ACK in the file |
| `reset` | an RST (which wins over FIN) and a SYN or SYN-ACK was seen — the port-scan shape |
| `reset_no_handshake_seen` | an RST on a connection whose opening is not in the file |
| `no_transport_seen` | the protocol byte said TCP but no flags byte was ever read: the IP-pair flow of packets cut before their transport header, fragments, or datagrams too short for what they claim |
| `null` | not TCP |

### Honesty stamps

| Condition | Where | Stamp |
|---|---|---|
| Source larger than the **256 MiB staging cap** | `NetworkCapture` | `content_incomplete` + `cap_reached`; every count on the record is of the staged prefix |
| Source read short of its declared size (short of the smaller of the file and the cap) | `NetworkCapture` | `content_incomplete` + `short_read`; the detail also names the cap when the cap would have bounded the read anyway |
| The block walk stopped early | `NetworkCapture` | `content_incomplete` + `short_read`, with `stopped.reason` / `stopped.at` and `bytes_read` |
| ISB drop counters > 0 | `NetworkCapture` | `content_incomplete` + `short_read` — the capture engine itself attesting it lost packets, the only place in the evidence that says so |
| Any packet captured short of its wire length | `NetworkCapture` and the flow | `content_incomplete` + `short_read`, with `truncated_packets` |
| Packets on an undeclared interface, or in a block too short to read | `NetworkCapture` | `content_incomplete` + `unresolved_structure` |
| Packets refused before their addresses could be read (a frame cut inside its link or IP header, a malformed IP header, more VLAN tags or IPv6 extension headers than are walked) | `NetworkCapture` | `content_incomplete` + `unresolved_structure`, listing the reasons: these reached no flow, so the capture record is the only one that can say what they were |
| ISB counters stated and unreadable; a packet block claiming more captured bytes than it held; a block trailer disagreeing with its header; an option list ending inside an option | `NetworkCapture` | `content_incomplete` + `unresolved_structure`, one sentence each |
| Some packets on a flow carried no timestamp | the flow | `content_incomplete` + `unresolved_structure`, naming how many of the flow's packets its times are over |
| Packets between a flow's two hosts refused before a port could be read | the port-level flow | `content_incomplete` + `unresolved_structure`: they are counted on the IP-pair flow, and may be this conversation's other half, so its direction counts and initiator are not complete |
| Port-53 payloads that did not decode as DNS, or were cut inside the DNS header | `NetworkCapture` | `inventory_incomplete` + `unresolved_structure` (`dns_undecodable`) or `short_read` (`dns_header_short`) |
| Flow cap (500,000) or DNS cap (100,000) reached | `NetworkCapture` | `inventory_incomplete` + `cap_reached`, naming the cap and the packets past it |
| A refused packet counted on an IP pair | the flow | `content_incomplete` — `short_read` when the transport header was cut by the capture, `unresolved_structure` when the bytes were present and not trusted (checksum, fragment, a datagram too short for what it claims) |
| A DNS message the capture cut | `DnsResolution` | `content_incomplete` + `short_read`; the records fully read before the cut are kept |
| An interface on a LINKTYPE not decoded | its `NetworkCaptureRefusal` | `content_incomplete` + `unresolved_structure` |
| Detected as a capture, refused by the reader | one `NetworkCaptureRefusal` | both stamps, `unresolved_structure`, the error named |

**Every `NetworkFlow` and `DnsResolution` record inherits the capture-wide
stamps** — everything in the table above placed on `NetworkCapture` except the
snaplen row, which stays on the flows it touched — with the detail "the capture
this record was drawn from is incomplete: …". A record's own reason wins where
it has one; the capture's detail is appended. A flow quoted on its own therefore
says that the file it came from was short, capped, or attested by its engine to
have lost packets, without the examiner having to go back to the capture record.

### Not done, and said so

- **Streaming.** The capture is staged into memory up to 256 MiB and read as a
  prefix past that. Reading through `SourceCursor` is not done, so a capture of tens of gigabytes is reported as its
  first 256 MiB with the `cap_reached` stamp.
- **Export objects as a saved set, expert info, and the protocol statistics.**
  Reassembly, HTTP and TLS are described under **Stage 2** above. What
  Wireshark has and this does not is the export-objects *dialogue*: each body
  here is an artifact in the case, hashed and scanned like any other file,
  rather than a file the examiner saves out by hand.
- **A packet list.** Flows are the unit; packets are counted, never
  enumerated.
- **Name resolution and geolocation from anywhere but the capture.** Not a
  gap; a rule, inherited verbatim from `MemoryNetworkPage`.

---

## Encrypted volumes

### BitLocker — `seance_plugin_bitlocker`

**Status:** ✅ detection and reporting; ✅ decryption for the modern ciphers.

**Detection is not conditional on holding the key.** Whether a volume is
encrypted is a fact about the evidence; whether anyone can open it is a fact
about this run, and collapsing the two is how an encrypted volume becomes
silence in the case file. `BitlockerDecryptor::process` therefore tests
`is_bitlocker` **before** it looks at the credential.

**A locked volume with no credential is reported, with what its own metadata
says about it.** BitLocker leaves its three FVE metadata blocks unencrypted, so
the following are readable on any locked volume and are published on a
`VolumeDecryption` record with `status = "NotUnlocked"`:

| Field | Source |
|---|---|
| `bitlocker_encryption_method` | FVE metadata cipher id, e.g. `AES-XTS 256-bit` |
| `bitlocker_volume_identifier` | FVE volume GUID, rendered in Microsoft's mixed-endian text form so it matches `manage-bde` output and recovery-key escrow records |
| `bitlocker_key_protectors` | Human labels, in metadata order — what an examiner would have to obtain to open the volume |
| `sector_size` | Bytes per sector from the VBR's BPB |

A volume whose VBR identifies it as BitLocker but whose FVE metadata blocks
cannot be read is **still reported**, with the cipher recorded as
`unknown (FVE metadata unreadable)`. Failing to describe the cipher is a fact
about the image and no reason to report the volume as unencrypted.

Every not-opened outcome carries the standard incompleteness pair
(`content_incomplete` / `inventory_incomplete`, reason `encrypted`) so the case
incompleteness census counts it, and the three outcomes are kept apart because
they are different findings:

| `status` | Means |
|---|---|
| `NotUnlocked` | Encrypted; no credential was supplied for this run |
| `UnlockFailed` | A credential was supplied and did not unlock the key hierarchy |
| `CipherNotDecryptable` | The credential worked, the FVEK was recovered, and this build cannot decrypt that cipher |

**Decryption depth:**

| Cipher | Key recovery | Sector decryption |
|---|---|---|
| AES-XTS 128 / 256 (Windows 10+) | ✅ | ✅ |
| AES-CBC + Elephant diffuser 128 / 256 (Vista/7/8) | ✅ | ✅ |
| Plain AES-CBC 128 / 256 (`0x8002`/`0x8003`) | ✅ | ❌ reported as `CipherNotDecryptable` |

**Sector size is a refusal, not a guess.** The XTS tweak is per-sector, so this
build decrypts XTS volumes at **512 bytes per sector only**. A volume declaring
anything else — 4Kn, or a VBR that carried no size at all — is reported as
detected and left undecrypted, because decrypting on the wrong sector size
produces bytes for every sector and correct bytes for none, and nothing
downstream can tell that from a volume full of noise.

**Presentation.** An unlocked volume is not handed to the filesystem parsers as
a bare decrypting view: BitLocker's own VBR sits at sector 0 and the real boot
sector is relocated, so `BitlockerVolumeSource` puts the real header back at the
front and passes the unencrypted FVE metadata regions through rather than
ciphering them into noise. Without that, a fully recovered volume fails NTFS
parsing in the way that looks like an unformatted disk.

**Credentials** come two ways. For one volume after ingest, the
recovery password or the password goes to `POST
/cases/{id}/artifacts/{id}/credential`, reaches the module for that one run and
is tried first; this was validated on `test_data/bdetogo.raw` (password) and on
the Windows 11 corpus volume (recovery password), each with a wrong secret
rejected. For the whole run, `--bitlocker-password` / `--bitlocker-recovery-key`
(a password wins if both are given) are held on the module in process memory.
Neither is ever written to artifact metadata — a `Debug` of the module prints
the kind of credential, never its value — and a `Credential`'s text is zeroed
when it drops. A successful unlock writes the decrypted volume and a
`VolumeDecryption` record of `status: Unlocked`.

**Validation.** Detection, FVE parsing, password key derivation and the AES-CCM
unwrap of the VMK and FVEK were validated byte-for-byte against a real Windows
BitLocker-To-Go volume (`test_data/bdetogo.raw`, password `bde-TEST`), and the
XTS path against the Windows 11 25H2 XTS-AES-256 corpus in
`test_data/win11_bitlocker/`. See `test_data/README.md`.

**Not claimed:** recovering an FVEK from a memory capture. Nothing in the tree
does this — `grep -rni fvek` outside `seance_plugin_bitlocker/` returns nothing.
The only ways in are a password, a recovery password, or `seance_cli crack-bitlocker`
against a wordlist or mask.

### LUKS1 / LUKS2 — `seance_plugin_luks`

**Status:** ✅ decryption with a passphrase; ✅ reported as locked without one.

`unlock_luks` parses the header and, for each active keyslot, derives the
keyslot key (PBKDF2 for LUKS1; PBKDF2 or Argon2 for LUKS2), decrypts the
anti-forensic material, AF-merges it to a candidate master key and verifies it
against the stored digest. Only the AES-XTS cipher family
(`aes-xts-plain64`, the LUKS default) is supported; any other cipher returns
`LuksError::Unsupported`.

A **failed** unlock produces a `VolumeDecryption` record carrying the standard
incompleteness pair, so a wrong passphrase cannot be mistaken for an
unencrypted volume (B3-084). A run with **no** passphrase produces the same
record shape with `subtype: detected_locked` and `status: NotUnlocked`, carrying
what the plaintext header states — LUKS version, cipher, UUID (LUKS1) and the
number of active keyslots — so the volume reaches the Needs attention queue. A volume that is not LUKS still produces nothing.

The passphrase can be supplied for one volume after ingest (`kind: luks_passphrase` on the credential route), tried before the process-level
`--luks-passphrase`. Graded on LUKS1 and LUKS2 volumes formatted by the real
`cryptsetup luksFormat` on a file (`tests/cryptsetup_credential.rs`, run where
`cryptsetup` is installed): the passphrase recovers a master key whose digest
verifies, and a wrong one is rejected. The payload is not opened through
dm-crypt there (that needs root), so the plaintext round trip remains
`tests/roundtrip.rs`'s, on images this project encodes.

`seance_cli crack-luks` takes a wordlist or mask against a LUKS volume.

### APFS FileVault and Apple encrypted disk images

**Status:** ✅ detected and disclosed; ❌ not decrypted.

- **An encrypted APFS volume** (`apfs_fs_flags` without `APFS_FS_UNENCRYPTED`)
  is emitted as a `FileSystem` record with `encrypted: true` and the filesystem
  walk is skipped. Its bytes are still served, which is how a locked container
  is exported.
- **A per-extent-encrypted file** on an otherwise readable volume has its
  encrypted extents emitted as holes, with `content_encrypted: true`,
  `content_incomplete_reason: "apfs_extent_encrypted"` and an
  `encrypted_extent_count`. Content is withheld rather than served as
  ciphertext that would carve into nonsense.
- **An encrypted Apple disk image** opens with the magic `encrcdsa` — the same
  constant `seance_carving`'s FileVault signature carves on. `seance_core::file_detection`
  does not know this format and there is no `.dmg` extension entry, so ingest
  reads the magic directly and stamps `encrypted: true`,
  `encryption_format: "apple_encrypted_dmg"` and the standard incompleteness
  pair, so the source is counted by the case incompleteness census instead of
  showing an artifact count of zero.

Neither is decrypted. `libfvde`-style volume-key recovery is design-only — see
`documentation/MACOS_DESIGN.md`.

---

## RAID / JBOD / LVM reassembly

### Status: ✅ Shipped, CLI-reached

**Crate:** `seance_container_raid`
**Not registered as a `ForensicsModule`** — it is invoked from `seance_cli`
(`seance_container_raid::{assemble, RaidDevice, RaidLevel}`), because assembling
an array is an examiner's decision about which member images belong together,
not something to infer inside the pipeline. `seance_plugin_partition` also uses
its `md` superblock parser, to keep a coincidental magic from being read as an
array.

- `raid` — RAID 0/1/5/6 and JBOD geometry, with single-member parity rebuild
  (a missing member is passed as `None` and reconstructed).
- `md` — geometry auto-detected from a Linux `md` v1 superblock.
- `lvm` — LVM2 metadata parsed and a logical volume mapped onto its PV.

The result is one `DataSource`, so every downstream filesystem, carver and
parser runs unchanged. `AssemblyReport` records how the geometry was
determined — level, chunk, member size, data offset — for the audit trail; when
the array is foreign and carries no superblock, `RaidDevice` takes the geometry
explicitly rather than guessing it.

---

## The decompression ceiling

Every expander in `seance_container_archive` works under one ceiling on the
size of a decompressed stream: **10 GiB by default**, overridable with
`SEANCE_MAX_DECOMPRESSED_BYTES`.

The ceiling travels with the fact of whether an examiner chose it
(`limits::Ceiling { bytes, from_env }`), because "10 GiB because nobody set
anything" and "10 GiB because somebody set 10G" are the same number and
different facts, and only the second is a decision about this examination that a
court might ask about. A value that fails to parse counts as **not chosen**: the
built-in default governed the evidence, and recording otherwise would put a
choice on the record nobody made.

---

## Format Comparison

| Feature | E01/EWF | AFF4 | `.sparseimage` | ZIP | RAW |
|---------|---------|------|----------------|-----|-----|
| **Status** | ✅ Production | ✅ Production | ✅ Shipped | ✅ Production | ✅ Production |
| **Compression** | ✅ Deflate | ✅ Snappy/Deflate | ❌ None (sparse, not compressed) | ✅ Stored/Deflate/bzip2/zstd | ❌ None |
| **Checksums** | ✅ Adler32 (inside libewf) | ⚠️ Per-entry CRC-32 only, by the ZIP layer | ❌ None in format | ✅ CRC32 | ❌ None |
| **Metadata** | ✅ Rich | ✅ Turtle/RDF | ⚠️ Geometry only | ✅ Basic | ❌ None |
| **Multi-segment** | ✅ Yes | ✅ Striped | ❌ No | ❌ No | ❌ No |
| **Industry Standard** | ✅ Yes | ⚠️ Emerging | ⚠️ Reverse-engineered (libmodi) | ✅ Yes | ✅ Yes |
| **Read Performance** | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ |

---

## Testing

### E01 Tests

**Test Suite:** `seance_tests/src/e01_tests.rs`
**Tests:** 3/3 passing

```bash
cargo test --package seance_tests e01
```

**Tests:**
- `test_module_metadata` - Module identification
- `test_non_e01_file_ignored` - Graceful handling of non-E01 files
- `test_e01_file_detection` - E01 file detection logic

**None of those three reads an image.** They are routing assertions. The
reading of a real image is pinned by two corpus-gated checks, and both **skip**
when their fixture is absent: `seance_container_e01/tests/isolation_test.rs`
decodes `test_data/canon2/nps-2009-canon2-gen6.E01` through the isolated
helper and compares the MD5, and `seance_validate` case WIN-1 reads
`alihadi_ntfs/NTFS-HiddenFiles.E01` through the in-process reader and
reproduces FTK Imager's acquisition log. Neither fixture is in the
repository.

### AFF4 Tests

**Test Suite:** `seance_tests/src/aff4_tests.rs`
**Tests:** 4/4 passing

```bash
cargo test --package seance_tests aff4
```

**Tests:**
- `test_module_metadata` - Module identification
- `test_non_aff4_file_ignored` - Graceful handling of non-AFF4 files
- `test_aff4_file_detection` - AFF4 file detection logic
- `test_aff4_reader_is_implemented` - End-to-end reconstruction of a container

### Per-crate unit and integration tests

Counted as `#[test]` / `#[tokio::test]` declarations in each crate's `src/` and
`tests/`. These are the crate's own tests; the `seance_tests`
integration suites above are separate, and the corpus-gated cases (BitLocker
against `test_data/win11_bitlocker/` and `test_data/bdetogo.raw`) skip when
their images are absent — see `test_data/README.md`.

| Crate | Tests |
|---|---|
| `seance_container_archive` | 82 |
| `seance_container_raid` | 72 |
| `seance_container_vdisk` | 57 |
| `seance_plugin_bitlocker` | 31 |
| `seance_container_aff4` | 34 |
| `seance_container_zip` | 29 |
| `seance_container_e01` | 27 |
| `seance_plugin_luks` | 26 |
| `seance_container_sparseimage` | 8 |

The BitLocker corpus tests are **not** `#[ignore]`d — they run in a debug build
if the corpus is present, and decrypting 61 GiB unoptimised is slow enough that
`--release` is strongly advised:

```bash
cargo test --release -p seance_plugin_bitlocker
```

(The neighbouring Windows *memory* corpus tests in
`seance_plugin_memory_windows/tests/win11_corpus_analysis.rs` **are**
`#[cfg_attr(debug_assertions, ignore)]`, so those report as *ignored* rather
than passing over nothing in a debug build. The two crates differ; do not
assume one from the other.)

---

## Troubleshooting

### E01: libewf not found

**Error:** `Failed to initialize libewf handle`

**Solution:**
```bash
# macOS
brew install libewf

# Ubuntu/Debian
sudo apt-get install libewf-dev

# Verify installation
ewfinfo --version
```

### E01: Failed to open file

**Error:** `Failed to open E01 file: evidence.e01`

**Possible causes:**
1. File doesn't exist or path is incorrect
2. Multi-segment files - ensure all segments are in same directory
3. File permissions - check read access
4. Corrupted E01 file - verify with `ewfverify`

### AFF4: unsupported chunk compression

**Symptom:** an AFF4 image fails to read a region.

**Cause:** the image uses an unsupported chunk compression (e.g. LZ4). Seance
reads snappy- and deflate-compressed (and raw) chunks. Re-image or convert such
containers to E01 or raw.

---

## Development

### Adding a New Container Format

To add support for a new container format:

1. Create new crate: `seance_container_<format>`
2. Implement `ForensicsModule` trait
3. Create `DataSource` implementation if needed
4. Add detection logic in `process()`
5. Write integration tests
6. Update this documentation

**Example skeleton:**
```rust
pub struct MyContainerModule;

impl ForensicsModule for MyContainerModule {
    fn id(&self) -> &str { "container.my_format" }
    fn version(&self) -> &str { "0.1.0" }
    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::Container]
    }
    fn input_capability(&self) -> InputCapability {
        InputCapability::FilePath
    }
    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        // Fast path: check subtype first
        if let Some(subtype) = artifact.subtype() {
            if subtype != "my_format" {
                return Ok(Vec::new()); // Early exit - not our format
            }
        }

        // Detection and processing logic
        Ok(vec![])
    }
}
```

---

## References

### E01/EWF
- [EnCase Image File Format - ForensicsWiki](https://forensics.wiki/encase_image_file_format/)
- [E01 File Format Explained - Forensicsware](https://www.forensicsware.com/blog/e01-file-format/)
- [libewf Project - GitHub](https://github.com/libyal/libewf)

### AFF4
- [AFF4 Standard - GitHub](https://github.com/aff4/Standard)
- [Advanced Forensic Format 4 - Library of Congress](https://www.loc.gov/preservation/digital/formats/fdd/fdd000413.shtml)
- [AFF4 - ForensicsWiki](https://forensics.wiki/aff4/)
- [libaff4 (C++) - GitHub](https://github.com/Velocidex/c-aff4)
- [pyaff4 (Python) - GitHub](https://github.com/aff4/pyaff4)

### General
- [Digital Forensic File Formats - Library of Congress](https://www.loc.gov/preservation/digital/formats/fdd/browse_list.shtml)
