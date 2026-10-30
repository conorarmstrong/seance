"""List the timers of a legacy global timer table (Windows XP x64 / Server 2003 and later until the per-processor
table) with Volatility 2's address space, for the cases `windows.timers` and `timers` do not reach
(`MEM-059`, `VALIDATION.md` `MEM-XP-6`). Python 2, run inside the volatility 2.6.1 container:

  docker run --rm --entrypoint python2 -v DIR_WITH_IMAGE:/d -v SCRIPT_DIR:/s -v ISF_DIR:/i sk4la/volatility \
      /s/vol2_legacy_timers.py /d/mem.raw Win2003SP2x64 /i/<GUID>-<age>.json

The kernel base comes from the KDBG block; the table's address from the symbol's RVA in the ISF Seance converted
from the same PDB (the symbol file is shared, the walk is not); each of the 256 buckets is `_KTIMER_TABLE_ENTRY`
(from the ISF), each list item a `_KTIMER` through `TimerListEntry`. One line per list item: address, bucket, period, header type (8 or 9 for a timer). The bucket count is the fourth argument (default 256).
"""
import json
import sys

import volatility.conf as conf
import volatility.registry as registry
import volatility.utils as utils
import volatility.commands as commands
import volatility.addrspace as addrspace
import volatility.obj as obj
import volatility.win32.tasks as tasks

image, profile, isf_path = sys.argv[1:4]
isf = json.load(open(isf_path))
registry.PluginImporter()
config = conf.ConfObject()
registry.register_global_options(config, commands.Command)
registry.register_global_options(config, addrspace.BaseAddressSpace)
config.parse_options()
config.PROFILE = profile
config.LOCATION = "file://" + image
space = utils.load_as(config)
kdbg = tasks.get_kdbg(space)
base = int(kdbg.KernBase)
rva = isf["symbols"]["KiTimerTableListHead"]["address"]
table = base + rva
entry = isf["user_types"]["_KTIMER_TABLE_ENTRY"]
size = entry["size"]
list_off = entry["fields"]["Entry"]["offset"]
timer = isf["user_types"]["_KTIMER"]["fields"]
tle = timer["TimerListEntry"]["offset"]
period_off = timer["Period"]["offset"]
print("# kernel base %#x table %#x entry size %d" % (base, table, size))
seen = set()
BUCKETS = int(sys.argv[4]) if len(sys.argv) > 4 else 256
for bucket in range(BUCKETS):
    head = table + bucket * size + list_off
    flink = obj.Object("unsigned long long", offset=head, vm=space)
    n = 0
    cur = int(flink)
    while cur != head and cur and n < 4096:
        t = cur - tle
        if t in seen:
            break
        seen.add(t)
        period = obj.Object("unsigned long", offset=t + period_off, vm=space)
        # _DISPATCHER_HEADER.Type: 8 NotificationTimer, 9 SynchronizationTimer; anything else is not a timer.
        htype = int(obj.Object("unsigned char", offset=t, vm=space))
        print("%#x\t%d\t%d\t%d" % (t, bucket, int(period), htype))
        cur = int(obj.Object("unsigned long long", offset=cur, vm=space))
        n += 1
