#!/usr/bin/env python3
"""Tests for resolve-key-files.py (VAL-002).

    python3 scripts/cftt/test_resolve_key_files.py

`DataUnit` pins the sector-to-data-unit mechanism on synthetic geometry. It
stands for no validation on real evidence.

`AgainstTheRealImages` runs the resolver on the CFTT string-search images when
`SEANCE_CFTT_SS` names the fetched data set and The Sleuth Kit is installed,
and is skipped (saying why) otherwise. `cargo test -p seance_validate` runs
this file (`cftt::grade::the_key_file_resolver`), so a resolver regression
fails a gate.
"""
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unicodedata
import unittest

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "resolve-key-files.py")
_spec = importlib.util.spec_from_file_location("resolve_key_files", SCRIPT)
rkf = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rkf)

SET = "string-search-federated-testing-data-set-version-1-1-revised-september-27-2019"


class DataUnit(unittest.TestCase):
    """Synthetic geometry: the mechanism only."""

    def test_fat_and_exfat_are_addressed_by_sector(self):
        for fs in ("FAT12", "FAT16", "FAT32", "exFAT"):
            self.assertEqual(rkf.data_unit(fs, 18842, {"sector": 512, "cluster": 4096}),
                             (18842, None), fs)

    def test_ntfs_is_addressed_by_cluster(self):
        self.assertEqual(rkf.data_unit("NTFS", 80, {"sector": 512, "cluster": 4096}), (10, None))

    def test_ext4_is_addressed_by_its_block(self):
        # The unix image's Ext4 has 1 KiB blocks: sector 542494 of the
        # partition is block 271247 (row 0152).
        self.assertEqual(rkf.data_unit("Ext4", 542494, {"block": 1024}), (271247, None))

    def test_hfs_plus_and_hfsx_are_addressed_by_allocation_block(self):
        for fs in ("HFS+", "HFSX"):
            self.assertEqual(rkf.data_unit(fs, 195896, {"block": 4096}), (24487, None), fs)

    def test_an_unknown_file_system_is_could_not_look(self):
        unit, why = rkf.data_unit("APFS", 100, {"block": 4096})
        self.assertIsNone(unit)
        self.assertTrue(why.startswith("could not look"), why)

    def test_a_missing_size_is_could_not_look_not_assumed(self):
        for fs in ("NTFS", "Ext4", "HFS+"):
            unit, why = rkf.data_unit(fs, 100, {"sector": 512})
            self.assertIsNone(unit, fs)
            self.assertTrue(why.startswith("could not look"), why)


def _corpus():
    d = os.environ.get("SEANCE_CFTT_SS")
    if not d:
        return None, "SEANCE_CFTT_SS is not set"
    if any(shutil.which(t) is None for t in ("mmls", "fsstat", "ifind", "ffind")):
        return None, "The Sleuth Kit is not installed"
    return os.path.join(os.path.expanduser(d), SET), None


def _resolve(root, which):
    image = os.path.join(root, "copy-to-test-computer", f"ss-{which}-07-25-18.dd")
    key = os.path.join(root, f"{which}_string_doc.txt")
    if not (os.path.exists(image) and os.path.exists(key)):
        raise unittest.SkipTest(f"the {which} image or key is not present")
    with tempfile.TemporaryDirectory() as tmp:
        out = os.path.join(tmp, "key-files.json")
        p = subprocess.run([sys.executable, SCRIPT, image, key, out],
                           capture_output=True, text=True)
        rows = []
        if os.path.exists(out):
            with open(out, encoding="utf-8") as fh:
                rows = json.load(fh)
    # A list, not a map by id: the key repeats some ids (2952-2959 appear
    # three times each on the unix key).
    return p.returncode, rows, p.stderr


def _row(rows, rid):
    return next(r for r in rows if r["id"] == rid)


def _differ(rows):
    # NFC: HFS+ stores names decomposed, so `ffind` gives `cañón` as NFD.
    return {r["id"]: unicodedata.normalize("NFC", r["image_file"]) for r in rows
            if r["image_file"]
            and r["image_file"].lower() != os.path.basename(r["key_file"]).lower()}


class AgainstTheRealImages(unittest.TestCase):
    """Real evidence: the CFTT string-search images, checked with Sleuth Kit."""

    def setUp(self):
        self.root, why = _corpus()
        if self.root is None:
            self.skipTest(why)

    def test_the_windows_key_resolves_the_fourteen_known_substitutions(self):
        rc, rows, err = _resolve(self.root, "win")
        self.assertEqual(rc, 0, err)
        resolved = sum(1 for r in rows if r["image_file"])
        self.assertEqual((resolved, len(rows)), (707, 708), err)
        # The same fourteen as grade.rs TSK_KEY_FILES.
        self.assertEqual(_differ(rows), {
            "0928": "LIVE-thunderbird-fat-ascii.txt",
            "0929": "DELETED-thunderbird-fat-ascii.txt",
            "0930": "LIVE-thunderbird-exfat-ascii.txt",
            "0931": "DELETED-thunderbird-exfat-ascii.txt",
            "0932": "LIVE-thunderbird-ntfs-ascii.txt",
            "0933": "DELETED-thunderbird-ntfs-ascii.txt",
            "2625": "LIVE-cañón-fat-utf-8.txt",
            "2629": "DELETED-cañón-fat-utf-8.txt",
            "2633": "LIVE-cañón-exfat-utf-8.txt",
            "2637": "DELETED-cañón-exfat-utf-8.txt",
            "2641": "LIVE-cañón-ntfs-utf-8.txt",
            "2645": "DELETED-cañón-ntfs-utf-8.txt",
            "6000": "FRAG-fat-Sacramento-split-512.txt",
            "6006": "FRAG-fat-Olympia-split-32k.txt",
        })

    def test_the_unix_key_is_resolved_in_each_file_systems_own_unit(self):
        rc, rows, err = _resolve(self.root, "unix")
        self.assertEqual(rc, 0, err)
        # Ext4 (1 KiB blocks) and HFS+ (4 KiB allocation blocks): found by
        # hand with `ifind -o 978944 -d 271247` and `ifind -o 2048 -d 24487`.
        self.assertEqual(_row(rows, "0152").get("path"), "/ext4/LIVE-plot-ext4-ascii.txt")
        self.assertEqual(_row(rows, "0154").get("path"), "/osxj/LIVE-plot-osxj-ascii.txt")
        resolved = sum(1 for r in rows if r["image_file"])
        self.assertEqual((resolved, len(rows)), (356, 926), err)
        # The partition fsstat does not recognise is "could not look", never
        # "no file there".
        blind = [r for r in rows
                 if (r.get("unresolved") or "").startswith("could not look")]
        self.assertEqual(len(blind), 228)
        # The same aliases as on the Windows image, one per LIVE file system.
        self.assertEqual(_differ(rows), {
            "0936": "LIVE-thunderbird-ext4-ascii.txt",
            "0938": "LIVE-thunderbird-osxj-ascii.txt",
            "0940": "LIVE-thunderbird-osxc-ascii.txt",
            "2657": "LIVE-cañón-ext4-utf-8.txt",
            "2665": "LIVE-cañón-osxj-utf-8.txt",
            "2673": "LIVE-cañón-osxc-utf-8.txt",
        })


if __name__ == "__main__":
    unittest.main(verbosity=2)
