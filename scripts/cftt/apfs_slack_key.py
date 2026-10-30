#!/usr/bin/env python3
"""Write the file-slack answer key for one APFS partition from libfsapfs.

    PYTHONPATH=<dir holding pyfsapfs> python3 scripts/cftt/apfs_slack_key.py IMAGE SECTOR_OFFSET SECTORS > key.json

`pip install libfsapfs-python` (libyal) provides `pyfsapfs`. For every regular file with at least one
extent, libfsapfs gives the size and the extents `(physical byte offset, length, flags)` in file order; the
file's slack is the bytes from its logical end to the end of the allocation block holding its last byte.
The tail is read straight from the partition at the offset the extents name, so neither the offset nor the
bytes come from Seance. The key records, for each file whose tail is not all zero, the tail's offset in the
partition, its length and its SHA-256, and for each file whose tail is all zero the same offset and length
without a digest. Files with no extent (empty, or compressed or stored in an attribute) are counted apart.
"""
import hashlib
import io
import json
import sys

import pyfsapfs


class Window(io.RawIOBase):
    """A read-only file object over one partition of a raw image."""

    def __init__(self, path, start, length):
        self.f = open(path, "rb")
        self.start, self.length, self.p = start, length, 0

    def readable(self):
        return True

    def seekable(self):
        return True

    def seek(self, offset, whence=0):
        self.p = offset if whence == 0 else (self.p + offset if whence == 1 else self.length + offset)
        return self.p

    def tell(self):
        return self.p

    def read(self, n=-1):
        n = self.length - self.p if n < 0 else max(0, min(n, self.length - self.p))
        self.f.seek(self.start + self.p)
        data = self.f.read(n)
        self.p += len(data)
        return data

    def readinto(self, buf):
        data = self.read(len(buf))
        buf[: len(data)] = data
        return len(data)

    def get_size(self):
        return self.length


def main():
    image, sector, sectors = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
    start, length = sector * 512, sectors * 512
    container = pyfsapfs.container()
    container.open_file_object(Window(image, start, length))
    volume = container.get_volume(0)
    part = open(image, "rb")
    key = {"image_basename": image.rsplit("/", 1)[-1], "sector_offset": sector, "sectors": sectors,
           "files": {}, "zero_files": {}, "no_extent": 0, "no_tail": 0}

    def tail_of(entry, size):
        """(offset in partition, length) of the slack, or None if it is not on disk as a plain run."""
        pos = 0
        for k in range(entry.get_number_of_extents()):
            phys, run, flags = entry.get_extent(k)
            if flags != 0:
                return None
            if size - 1 < pos + run:
                block = 4096
                end = ((size + block - 1) // block) * block
                if end > pos + run:
                    return None
                return phys + (size - pos), end - size
            pos += run
        return None

    def walk(directory, path):
        for i in range(directory.get_number_of_sub_file_entries()):
            e = directory.get_sub_file_entry(i)
            name = e.get_name()
            full = path + "/" + name
            if e.get_file_mode() & 0o170000 == 0o040000:
                walk(e, full)
                continue
            if e.get_file_mode() & 0o170000 != 0o100000:
                continue
            size = e.get_size()
            if size == 0 or size % 4096 == 0:
                key["no_tail"] += 1
                continue
            if e.get_number_of_extents() == 0:
                key["no_extent"] += 1
                continue
            t = tail_of(e, size)
            if t is None:
                key["no_extent"] += 1
                continue
            offset, tail_len = t
            part.seek(start + offset)
            data = part.read(tail_len)
            record = {"inode": e.get_identifier(), "size": size, "offset": offset, "length": tail_len}
            if any(data):
                record["sha256"] = hashlib.sha256(data).hexdigest()
                key["files"][full] = record
            else:
                key["zero_files"][full] = record

    walk(volume.get_root_directory(), "")
    json.dump(key, sys.stdout, indent=1, sort_keys=True)
    print()


main()
