#!/usr/bin/env python3
"""List the event-subscription instances a CIM repository holds, read by dissect.cim.

    PYTHONPATH=<dir holding dissect.cim> python3 scripts/oracle/cim_subscriptions.py REPOSITORY_DIR > key.json

REPOSITORY_DIR holds INDEX.BTR, MAPPING1-3.MAP and OBJECTS.DATA. `dissect.cim` is AGPL-3.0 and is used only as
a run-time grader (`pip install dissect.cim`); none of its source is read into or ported to Seance. For
`root\\subscription` it prints every instance of the filter, consumer and binding classes with its properties.
"""
import json
import sys

from dissect.cim import CIM

CLASSES = ["__EventFilter", "ActiveScriptEventConsumer", "CommandLineEventConsumer",
           "NTEventLogEventConsumer", "LogFileEventConsumer", "SMTPEventConsumer", "__FilterToConsumerBinding"]


def plain(value):
    if isinstance(value, (bytes, bytearray)):
        return value.hex()
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def main():
    cim = CIM.from_directory(sys.argv[1])
    out = {}
    for ns in ("subscription",):
        namespace = cim.namespace(ns)
        for cls in CLASSES:
            found = []
            try:
                for inst in namespace.class_(cls).instances:
                    found.append({k: plain(v) for k, v in inst.properties.items()})
            except Exception as e:  # a class this repository never defined
                found.append({"__error": f"{type(e).__name__}: {e}"})
            out[f"root\\{ns}:{cls}"] = found
    json.dump(out, sys.stdout, indent=1, sort_keys=True)
    print()


main()
