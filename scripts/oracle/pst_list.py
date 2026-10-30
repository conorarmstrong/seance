#!/usr/bin/env python3
"""List every message of a PST/OST with libpff (pypff): node id, folder path, subject, attachment count,
and the first 60 characters of the plain-text body. The independent reader a store is graded against.

    PYTHONPATH=<dir holding pypff> python3 scripts/oracle/pst_list.py STORE.pst
"""
import sys

import pypff


def walk(folder, path, out):
    for i in range(folder.number_of_sub_messages):
        m = folder.get_sub_message(i)
        body = m.plain_text_body
        if isinstance(body, bytes):
            body = body.decode("utf-8", "replace")
        out.append((m.identifier, "/".join(path), m.subject or "", m.number_of_attachments, (body or "")[:60].replace("\n", " ").replace("\r", " ")))
    for i in range(folder.number_of_sub_folders):
        f = folder.get_sub_folder(i)
        walk(f, path + [f.name or ""], out)


def main():
    f = pypff.file()
    f.open(sys.argv[1])
    print("# content_type", f.content_type, "ascii_codepage", f.ascii_codepage)
    out = []
    walk(f.get_root_folder(), [], out)
    for nid, folder, subj, att, body in out:
        print(f"{nid:#x}\t{att}\t{folder}\t{subj}\t{body}")
    f.close()


main()
