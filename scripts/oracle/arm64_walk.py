#!/usr/bin/env python3
"""An independent VMSAv8-64 stage-1 walker for a 16 KiB, 4 KiB or 64 KiB granule, with and without TCR_EL1.DS (16 KiB only).

    python3 scripts/oracle/arm64_walk.py MEM_RAW TCR TTBR [--granule 14|12|16] [--ttbr1] [--spots N] [--seed S]

Written from ARM DDI 0487 D8 without reference to this crate's walker, to give the Rust
translation core a second answer to compare with. `MEM_RAW` is RAM saved from physical
0x40000000 (QEMU `virt`); `TCR` and `TTBR` are the register values read off the paused
machine. The regime (TTBR0 or TTBR1) is taken from bit 55 of the walked addresses, so
`--ttbr1` says which half is walked.

Rules used, with DS = TCR_EL1.DS (16 KiB granule, 11 bits per level, page shift 14):

* the start level is the level whose index field holds the top of the input address (level 1
  with 2,048 entries at a 47-bit width, level 0 with 32 entries at a 52-bit width);
* a descriptor is invalid unless bit 0 is set; at level 3 bit 1 set is a page and clear is
  reserved; at levels 0-2 bit 1 set is a table; clear is a block at level 2, and at level 1
  only with DS = 1 (64 GiB); a level-0 block is reserved at this granule;
* output and next-table addresses are bits 47:14, plus bits 49:48 as bits 49:48, plus, when
  DS = 1, bits 9:8 as address bits 51:50 (which without DS are the shareability field);
* a block's address ignores the bits below its size.

Prints one JSON object: leaf counts by size, the order-independent digest the Rust test uses
(`sum(mix(va) ^ mix(pa + size))` over every leaf, modulo 2^64), how many leaves used an
address bit above 47, spot translations and the faults.
"""
import argparse
import json
import random
import struct

RAM_BASE = 0x4000_0000
MASK64 = (1 << 64) - 1


def mix(x):
    x = (x + 0x9E3779B97F4A7C15) & MASK64
    x = ((x ^ (x >> 30)) * 0xBF58476D1CE4E5B9) & MASK64
    x = ((x ^ (x >> 27)) * 0x94D049BB133111EB) & MASK64
    return x ^ (x >> 31)


class Walker:
    def __init__(self, ram, tcr, ttbr, high, granule=14):
        self.ram = ram
        self.high = high
        self.granule = granule
        self.tcr = tcr
        self.bits = granule - 3  # index bits per level: 11 at 16 KiB, 9 at 4 KiB
        self.entries = 1 << self.bits
        self.ds = (tcr >> 59) & 1 if granule == 14 else 0
        tsz = (tcr >> (16 if high else 0)) & 0x3F
        self.ia_bits = 64 - tsz
        self.page_shift = granule
        # shift of the VA field a level indexes: level 3 -> granule, level 2 -> granule + bits, ...
        self.shift = {l: granule + self.bits * (3 - l) for l in (3, 2, 1, 0)}
        # the level whose index field holds the top of the input address (1 to `bits` bits of it)
        self.start = next(l for l in (3, 2, 1, 0) if self.shift[l] < self.ia_bits <= self.shift[l] + self.bits)
        n_top = 1 << (self.ia_bits - self.shift[self.start])
        # the table's base is aligned to its size and held in TTBR bits 47:1 (and 5:2 for 51:48)
        size = max(n_top * 8, 64)
        base = ttbr & 0x0000_FFFF_FFFF_FFFE
        base |= ((ttbr >> 2) & 0xF) << 48 if self.ds else 0
        self.root = base & ~(size - 1)
        self.n_top = n_top

    def read(self, pa):
        off = pa - RAM_BASE
        if off < 0 or off + 8 > len(self.ram):
            return None
        return struct.unpack_from("<Q", self.ram, off)[0]

    def out_addr(self, d, shift):
        pa = d & 0x0000_FFFF_FFFF_FFFF & ~((1 << self.granule) - 1)
        if self.granule == 14:
            pa |= ((d >> 48) & 3) << 48
        if self.granule == 16:
            pa |= ((d >> 12) & 0xF) << 48  # FEAT_LPA: bits 15:12 are address bits 51:48
        if self.ds:
            pa |= ((d >> 8) & 3) << 50
        return pa & ~((1 << shift) - 1)

    def classify(self, d, level):
        """-> ('invalid'|'reserved'|'table'|'leaf', bytes)."""
        if not d & 1:
            return ("invalid", 0)
        if level == 3:
            return ("leaf", 1 << self.granule) if d & 2 else ("reserved", 0)
        if d & 2:
            return ("table", 0)
        if level == 2 or (level == 1 and (self.ds or self.granule == 12)):
            return ("leaf", 1 << self.shift[level])
        return ("reserved", 0)

    def leaves(self):
        """Yield (va, pa, size, used_high_bits) over every leaf; collect anomalies."""
        out, odd = [], []
        self.table_attrs, self.invalid_nonzero, self.tables = {}, [], 0
        self.nx = self.nx_forced = 0
        # hierarchical permission controls apply unless TCR_EL1.HPDn (bit 42 for TTBR1, 41 for TTBR0) is set
        self.hpd = (self.tcr >> (42 if self.high else 41)) & 1

        def walk(table_pa, level, va_prefix, n_entries, xn_table=False):
            for i in range(n_entries):
                d = self.read(table_pa + 8 * i)
                if d is None:
                    odd.append(("unreadable", table_pa + 8 * i))
                    continue
                kind, size = self.classify(d, level)
                va = va_prefix | (i << self.shift[level])
                if kind == "invalid":
                    if d:
                        top = ((MASK64 << self.ia_bits) & MASK64) if self.high else 0
                        self.invalid_nonzero.append((level, d, top | va, table_pa + 8 * i))
                    continue
                if kind == "reserved":
                    odd.append(("reserved", level, d))
                    continue
                if kind == "leaf":
                    own = bool(d >> (53 if self.high else 54) & 1)  # PXN under TTBR1, UXN under TTBR0
                    self.nx += own or xn_table
                    self.nx_forced += (not own) and xn_table
                    pa = self.out_addr(d, self.shift[level])
                    out.append((va, pa, size, bool((self.granule == 14 and (d >> 48) & 3) or (self.granule == 16 and (d >> 12) & 0xF) or (self.ds and (d >> 8) & 3))))
                else:
                    self.tables += 1
                    if d >> 59:
                        self.table_attrs[(level, d >> 59)] = self.table_attrs.get((level, d >> 59), 0) + 1
                    nxt = self.out_addr(d, self.granule)
                    folded = xn_table or (not self.hpd and bool(d >> (59 if self.high else 60) & 1))
                    walk(nxt, level + 1, va, self.entries, folded)

        walk(self.root, self.start, 0, self.n_top)
        if self.high:
            out = [(((MASK64 << self.ia_bits) & MASK64) | va, pa, s, h) for va, pa, s, h in out]
        return out, odd

    def translate(self, va):
        table, level = self.root, self.start
        top = va & ((1 << self.ia_bits) - 1)
        while True:
            idx = (top >> self.shift[level]) & ((self.n_top if level == self.start else self.entries) - 1)
            entry_pa = table + 8 * idx
            d = self.read(entry_pa)
            kind, size = self.classify(d, level)
            if kind == "invalid":
                return ("fault", level, d, entry_pa)
            if kind == "reserved":
                return ("reserved", level, d, entry_pa)
            if kind == "leaf":
                pa = self.out_addr(d, self.shift[level]) | (top & ((1 << self.shift[level]) - 1))
                return ("ok", pa, size)
            table, level = self.out_addr(d, self.granule), level + 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mem")
    ap.add_argument("tcr", type=lambda s: int(s, 0))
    ap.add_argument("ttbr", type=lambda s: int(s, 0))
    ap.add_argument("--ttbr1", action="store_true")
    ap.add_argument("--granule", type=int, default=14, choices=(12, 14, 16))
    ap.add_argument("--spots", type=int, default=24)
    ap.add_argument("--seed", type=int, default=1)
    a = ap.parse_args()
    import mmap

    f = open(a.mem, "rb")
    ram = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
    w = Walker(ram, a.tcr, a.ttbr, a.ttbr1, a.granule)
    leaves, odd = w.leaves()
    by_size, digest, high = {}, 0, 0
    for va, pa, size, h in leaves:
        by_size[size] = by_size.get(size, 0) + 1
        digest = (digest + (mix(va) ^ mix((pa + size) & MASK64))) & MASK64
        high += h
    rnd = random.Random(a.seed)
    spots = []
    for va, pa, size, _ in rnd.sample(leaves, min(a.spots, len(leaves))):
        inner = rnd.randrange(size)
        r = w.translate(va + inner)
        assert r[0] == "ok" and r[1] == pa + inner, (hex(va), r)
        spots.append([va + inner, pa + inner, size])
    # Faults, two for every depth the walk can stop at: random addresses stop at the top level,
    # so the deeper ones are found beside mapped leaves.
    by_depth = {}
    span = 1 << w.ia_bits
    top = (MASK64 << w.ia_bits) & MASK64 if a.ttbr1 else 0
    candidates = [top | rnd.randrange(span) for _ in range(2000)]
    for va, _, size, _ in rnd.sample(leaves, min(4000, len(leaves))):
        base = va & ((1 << w.ia_bits) - 1)
        for step in (1, 2, 3, 5, 9, 17, 64, 513, 1025):
            for sign in (1, -1):
                v = base + sign * step * size
                if 0 <= v < span:
                    candidates.append(top | v)
    for va in candidates:
        r = w.translate(va)
        if r[0] == "fault":
            depth = r[1] - w.start
            if len(by_depth.setdefault(depth, [])) < 2:
                by_depth[depth].append([va, depth, r[2], r[3]])
    faults = [f for d in sorted(by_depth) for f in by_depth[d]]
    print(json.dumps({
        "ia_bits": w.ia_bits, "ds": w.ds, "start_level": w.start, "root": hex(w.root),
        "leaves_by_size": {hex(k): v for k, v in sorted(by_size.items())},
        "digest": hex(digest), "leaves_using_high_address_bits": high,
        "anomalies": odd[:10], "anomaly_count": len(odd),
        "table_descriptors": w.tables,
        "no_execute_leaves": w.nx, "no_execute_forced_by_a_table_descriptor": w.nx_forced,
        "table_descriptors_with_attribute_bits_63_59": {f"level{l}:{b:#x}": n for (l, b), n in sorted(w.table_attrs.items())},
        "invalid_descriptors_nonzero": len(w.invalid_nonzero), "invalid_nonzero_examples": [[l, hex(d)] for l, d, _, _ in w.invalid_nonzero[:5]],
        "invalid_nonzero_faults": [[va, l - w.start, d, ep] for l, d, va, ep in w.invalid_nonzero[:: max(1, len(w.invalid_nonzero) // 6)][:6]],
        "spots": spots, "faults": faults,
    }, indent=1))


main()
