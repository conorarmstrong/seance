#!/usr/bin/env python3
"""Synthesise a small ext4 disk image holding a real Outlook mailbox with
deleted mail, among ordinary folders and files, and write down what an
examiner should be able to find in it.

The ground truth is this script: the mailbox is a real version 14 store (the
NPS M57-Jean Administrator Outlook file, committed under
seance_plugin_email/tests/fixtures/pst_old/), and the deletion is made here, in
Python, by cutting a message node's entry out of the live node B-tree and
re-sealing that page's CRC, as a deletion rewrites it. What must come back is
therefore known from the untouched file and from libpff's reading of it, never
from Séance's own output.

    python3 scripts/synth/build_mail_case_image.py --out /tmp/mail_case

Needs only `mke2fs` (e2fsprogs): the image is populated with `mke2fs -d`, so no
root and no loop device. Writes <out>/mail_case.ext4 and <out>/expected.json.
"""
import argparse
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
DEFAULT_PST = os.path.join(
    ROOT, "seance_plugin_email", "tests", "fixtures", "pst_old",
    "m57_jean_administrator_outlook.pst")
# The node of the one message in that store: "Welcome to Microsoft Outlook
# 2000!", eight attachments, in the Inbox (libpff 20260926).
WELCOME_NID = 0x200024
WELCOME_SUBJECT = "Welcome to Microsoft Outlook 2000!"
MAILBOX_PATH = ("Documents and Settings/Jean/Local Settings/Application Data/"
                "Microsoft/Outlook/outlook.pst")

PAGE = 512
ANSI_ROOT, ANSI_TRAILER = 164, 12


def _crc_table():
    t = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ 0xEDB88320 if c & 1 else c >> 1
        t.append(c)
    return t


_T = _crc_table()


def ndb_crc(b):
    """The MS-PST CRC: zero-seeded, uninverted CRC-32."""
    c = 0
    for x in b:
        c = _T[(c ^ x) & 0xFF] ^ (c >> 8)
    return c


def live_nbt_leaf_pages(d):
    """Offsets of the live node B-tree's leaf pages (version 14, ANSI)."""
    ver = struct.unpack_from("<H", d, 10)[0]
    if ver not in (14, 15):
        sys.exit(f"this builder cuts version 14/15 stores, not version {ver}")
    nbt_ib = struct.unpack_from("<I", d, ANSI_ROOT + 4 + 4 * 4 + 4)[0]
    leaves, stack = [], [nbt_ib]
    while stack:
        ib = stack.pop()
        p = d[ib:ib + PAGE]
        c_ent, cb_ent, level = p[496], p[498], p[499]
        if level == 0:
            leaves.append(ib)
        else:
            for i in range(c_ent):
                e = p[i * cb_ent:(i + 1) * cb_ent]
                stack.append(struct.unpack_from("<I", e, 8)[0])
    return leaves


def cut_live_node(data, nid):
    """A copy of the store whose live node B-tree no longer lists `nid`."""
    d = bytearray(data)
    for ib in live_nbt_leaf_pages(d):
        p = bytearray(d[ib:ib + PAGE])
        c_ent, cb = p[496], p[498]
        for i in range(c_ent):
            if struct.unpack_from("<I", p, i * cb)[0] == nid:
                p[i * cb:(c_ent - 1) * cb] = p[(i + 1) * cb:c_ent * cb]
                p[(c_ent - 1) * cb:c_ent * cb] = bytes(cb)
                p[496] = c_ent - 1
                end = PAGE - ANSI_TRAILER
                struct.pack_into("<I", p, end + 8, ndb_crc(bytes(p[:end])))
                d[ib:ib + PAGE] = p
                return bytes(d)
    sys.exit(f"node {nid:#x} is in no live leaf page")


def lay_out(stage, pst_bytes):
    """A believable tree around the mailbox: ordinary folders and misc data."""
    def put(rel, content):
        path = os.path.join(stage, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(content if isinstance(content, bytes) else content.encode())
        return rel

    put(MAILBOX_PATH, pst_bytes)
    put("Documents and Settings/Jean/My Documents/notes.txt",
        "Remember: call the lawyer about the M57 contract.\n")
    put("Documents and Settings/Jean/My Documents/budget.csv",
        "item,amount\nrent,1200\nsalaries,5400\n")
    put("Documents and Settings/Jean/Desktop/shortcut.url",
        "[InternetShortcut]\nURL=http://www.m57.biz/\n")
    put("Program Files/Common Files/readme.txt", "shared components\n")
    put("Windows/Temp/~dd0001.tmp", bytes(range(256)) * 8)
    put("Windows/System32/config/README", "registry hives would be here\n")
    put("Users/Public/Documents/empty.dat", b"")
    put("tmp/random.bin", hashlib.sha256(b"seed").digest() * 512)
    return MAILBOX_PATH


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out", required=True)
    ap.add_argument("--pst", default=DEFAULT_PST)
    ap.add_argument("--size-mb", type=int, default=24)
    a = ap.parse_args()
    if not shutil.which("mke2fs"):
        sys.exit("mke2fs (e2fsprogs) is required")
    os.makedirs(a.out, exist_ok=True)
    original = open(a.pst, "rb").read()
    cut = cut_live_node(original, WELCOME_NID)
    image = os.path.join(a.out, "mail_case.ext4")
    with tempfile.TemporaryDirectory() as stage:
        mailbox = lay_out(stage, cut)
        if os.path.exists(image):
            os.remove(image)
        subprocess.run(
            ["mke2fs", "-q", "-t", "ext4", "-L", "MAILCASE", "-d", stage,
             image, f"{a.size_mb}M"], check=True)
    expected = {
        "image": os.path.basename(image),
        "image_sha256": hashlib.sha256(open(image, "rb").read()).hexdigest(),
        "mailbox_path_in_image": "/" + mailbox,
        "mailbox_sha256_untouched": hashlib.sha256(original).hexdigest(),
        "mailbox_sha256_as_planted": hashlib.sha256(cut).hexdigest(),
        "store_version": 14,
        "live_messages_in_planted_mailbox": 0,
        "deleted_message_that_must_be_recovered": {
            "node_id": hex(WELCOME_NID),
            "subject": WELCOME_SUBJECT,
            "folder": "Top of Personal Folders/Inbox",
            "attachments": 8,
            "known_from": "libpff reading the untouched file; the deletion is "
                          "this script's own edit of the live node B-tree",
        },
    }
    with open(os.path.join(a.out, "expected.json"), "w") as f:
        json.dump(expected, f, indent=2)
        f.write("\n")
    print(json.dumps(expected, indent=2))


if __name__ == "__main__":
    main()
