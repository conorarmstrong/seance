#!/usr/bin/env python3
"""List the recipient table of every message of a PST/OST with libpff (pypff): one line per recipient, the
message node id, the row number, and every cell as `tag:type=value` (strings and integers; binary as its length).
The independent reader the recipient tables read by `pst512` are graded against.

    PYTHONPATH=<dir holding pypff> python3 scripts/oracle/pst_recipients.py STORE.pst
"""
import sys

import pypff


def walk(folder):
    for i in range(folder.number_of_sub_messages):
        try:
            yield folder.get_sub_message(i)
        except OSError as e:  # libpff cannot read this message: say so, and go on
            print("# skipped message %d of %s: %s" % (i, folder.name, str(e)[:60]))
    for i in range(folder.number_of_sub_folders):
        yield from walk(folder.get_sub_folder(i))


def cell(entry):
    t = entry.value_type
    try:
        if t in (0x1F, 0x1E):
            v = entry.get_data_as_string()
        elif t in (0x02, 0x03, 0x0A, 0x14):
            v = entry.get_data_as_integer()
        elif t == 0x0B:
            v = int(bool(entry.get_data_as_boolean()))
        else:
            v = "len%d" % len(entry.get_data() or b"")
    except Exception as e:  # a cell libpff cannot decode is listed, not skipped
        v = "ERR"
    if isinstance(v, str):  # a display name can hold a tab; the output is tab-separated
        v = v.replace("\t", "\\t").replace("\n", "\\n")
    return "%04x:%04x=%s" % (entry.entry_type, t, v)


def main():
    f = pypff.file()
    f.open(sys.argv[1])
    print("# content_type", f.content_type, "ascii_codepage", f.ascii_codepage)
    for msg in walk(f.get_root_folder()):
        r = getattr(msg, "recipients", None)
        if r is None:
            continue
        for row in range(r.number_of_record_sets):
            rs = r.get_record_set(row)
            cells = sorted(cell(rs.get_entry(i)) for i in range(rs.number_of_entries))
            print("%#x\t%d\t%s" % (msg.identifier, row, "\t".join(cells)))
    f.close()


main()
