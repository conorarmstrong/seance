#!/usr/bin/env python3
"""Cut the committed BITS queue fixtures from the Data Leakage PC's whole files.

Usage: make_fixtures.py <dir holding qmgr0.dat and qmgr1.dat>

The whole files come from the NIST CFReDS Data Leakage PC image
(cfreds_2015_data_leakage_pc.E01), NTFS partition at sector 206848:
    icat -o 206848 cfreds_2015_data_leakage_pc.E01 15553 > qmgr0.dat
    icat -o 206848 cfreds_2015_data_leakage_pc.E01 15554 > qmgr1.dat

Each fixture is the first 8,192 bytes of its file, unedited. The script
refuses to cut if any byte past the cut is non-zero, so the cut provably
drops nothing but zeros, and it rewrites MANIFEST.json.
"""
import hashlib, json, os, sys

CUT = 8192
FILES = {"qmgr0.dat": ("data_leakage_qmgr0.dat.head8k", 15553),
         "qmgr1.dat": ("data_leakage_qmgr1.dat.head8k", 15554)}

def main(src):
    here = os.path.dirname(os.path.abspath(__file__))
    manifest = {"source_image": "NIST CFReDS Data Leakage PC, cfreds_2015_data_leakage_pc.E01",
                "partition_offset_sectors": 206848,
                "path": "/ProgramData/Microsoft/Network/Downloader/",
                "cut_bytes": CUT, "files": []}
    for name, (fixture, inode) in FILES.items():
        data = open(os.path.join(src, name), "rb").read()
        if any(data[CUT:]):
            sys.exit(f"{name}: non-zero bytes past {CUT}; refusing to cut")
        open(os.path.join(here, fixture), "wb").write(data[:CUT])
        manifest["files"].append({
            "source": name, "mft_entry": inode, "source_bytes": len(data),
            "source_sha256": hashlib.sha256(data).hexdigest(),
            "fixture": fixture, "fixture_sha256": hashlib.sha256(data[:CUT]).hexdigest(),
        })
    with open(os.path.join(here, "MANIFEST.json"), "w") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")

if __name__ == "__main__":
    main(sys.argv[1])
