#!/usr/bin/env python3
"""Cut the fixtures in this directory from three real CIM repositories.

Each fixture is a concatenation of whole 8192-byte pages copied verbatim from a
real OBJECTS.DATA, in ascending page order. Nothing inside a page is altered, so
every record, descriptor table, checksum and heap is exactly as Windows wrote it;
only pages that carry nothing the tests need are left out. The page list and the
SHA-256 of both the source file and the fixture are written to MANIFEST.json.

The "sparse" fixture is cut the same way, but the test that reads it puts each
page back at its own physical page number (MANIFEST.json's page list), because
the page mapping names physical pages.

The mapping files (MAPPING1/2/3.MAP from Vista onward, OBJECTS.MAP on XP) are
small and are copied whole and unaltered (HUNT-195).

Sources (all public corpora, extracted with The Sleuth Kit's `icat`):

  lonewolf        Digital Corpora "Lone Wolf" scenario, LoneWolf.E01, Windows 10,
                  partition at sector 1259520: \\Windows\\System32\\wbem\\Repository\\
                  OBJECTS.DATA (MFT 89187), MAPPING1.MAP (89212)
  cfreds_xp       NIST CFReDS "Hacking Case", 4Dell_Latitude_CPi.E01, Windows XP,
                  partition at sector 63: \\WINDOWS\\system32\\wbem\\Repository\\FS\\
                  OBJECTS.DATA (MFT 5507), OBJECTS.MAP (11943)
  data_leakage    NIST CFReDS "Data Leakage Case", cfreds_2015_data_leakage_pc.E01,
                  Windows 7, partition at sector 206848:
                  \\Windows\\System32\\wbem\\Repository\\MAPPING1/2/3.MAP (58922-58924)

Usage: make_fixtures.py <lonewolf Repository dir> <cfreds FS dir> <data leakage Repository dir>
(each directory holding the extracted files under their Windows names)
"""
import hashlib
import json
import os
import sys

PAGE = 8192

# Pages chosen by locating, with `strings -t x` and an independent Python
# decoder, the class definitions and the class instances the tests assert on.
FIXTURES = {
    "lonewolf-win10-objects-pages.bin": {
        "source": "lonewolf",
        "pages": [0, 1, 112, 130, 140, 143, 148, 1316, 2645],
    },
    "cfreds-xp-objects-pages.bin": {
        "source": "cfreds_xp",
        "pages": [0, 9, 58, 254, 328, 357],
    },
    # HUNT-195, read back at physical positions. Page 42 opens the
    # Win32_ComputerSystem class definition, which runs on into logical page
    # 45 -- physical page 45, not the physically next page 43 (kept, so the
    # test shows the neighbour is not what is read). Page 2713 is a page
    # MAPPING1.MAP maps to no logical page; it holds one descriptor.
    "lonewolf-win10-objects-sparse.bin": {
        "source": "lonewolf",
        "pages": [42, 43, 45, 2713],
    },
}

# Whole mapping files, copied unaltered: (fixture name, source, file name).
WHOLE_FILES = [
    ("lonewolf-win10-MAPPING1.MAP", "lonewolf", "MAPPING1.MAP"),
    ("dataleakage-win7-MAPPING1.MAP", "data_leakage", "MAPPING1.MAP"),
    ("dataleakage-win7-MAPPING2.MAP", "data_leakage", "MAPPING2.MAP"),
    ("dataleakage-win7-MAPPING3.MAP", "data_leakage", "MAPPING3.MAP"),
    ("cfreds-xp-OBJECTS.MAP", "cfreds_xp", "OBJECTS.MAP"),
]


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> None:
    dirs = {"lonewolf": sys.argv[1], "cfreds_xp": sys.argv[2], "data_leakage": sys.argv[3]}
    manifest = {}
    for name, spec in FIXTURES.items():
        src_path = os.path.join(dirs[spec["source"]], "OBJECTS.DATA")
        src = open(src_path, "rb").read()
        out = b"".join(src[p * PAGE : (p + 1) * PAGE] for p in spec["pages"])
        open(name, "wb").write(out)
        manifest[name] = {
            "source": spec["source"],
            "source_size": len(src),
            "source_sha256": sha256(src),
            "pages": spec["pages"],
            "fixture_sha256": sha256(out),
        }
    for name, source, file_name in WHOLE_FILES:
        data = open(os.path.join(dirs[source], file_name), "rb").read()
        open(name, "wb").write(data)
        manifest[name] = {
            "source": source,
            "source_file": file_name,
            "source_size": len(data),
            "source_sha256": sha256(data),
            "fixture_sha256": sha256(data),
        }
    json.dump(manifest, open("MANIFEST.json", "w"), indent=2)
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
