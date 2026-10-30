#!/usr/bin/env python3
"""List every instance of the event-subscription classes of a CIM repository with python-cim (flare-wmi 1.1), the
independent reader the WMI index walk of Seance is graded against (`HUNT-195`, `VALIDATION.md` WMI-7).

    PYTHONPATH=<dir holding cim> python3 scripts/oracle/wmi_cim_instances.py REPOSITORY_DIR

One line per instance: namespace, class, then the Name (or the Filter and Consumer of a binding) as the repository
spells it. `--counts` prints instead the number of classes and of instances of every class of every namespace.
"""
import logging
import sys

import cim
from cim import CIM
from cim.objects import Namespace

SUBSCRIPTION = ("__EventFilter", "__FilterToConsumerBinding", "__EventConsumer")


def val(inst, key):
    try:
        return inst.properties[key].value
    except Exception:
        return None


def namespaces(ns, path, out):
    out.append(path)
    for child in ns.namespaces:
        namespaces(child, path + "\\" + child.name.split("\\")[-1], out)


def main():
    logging.disable(logging.CRITICAL)
    repo = sys.argv[1]
    counts = "--counts" in sys.argv
    # `--type=xp` for a Windows XP or Server 2003 repository (the `FS` directory), the default is the Vista/7 form.
    kind = cim.CIM_TYPE_XP if "--type=xp" in sys.argv else cim.CIM_TYPE_WIN7
    c = CIM(kind, repo)
    with Namespace(c, "root") as root:
        paths = []
        namespaces(root, "root", paths)
    for path in paths:
        with Namespace(c, path) as ns:
            subclasses = []
            for cl in ns.classes:
                name = cl.class_name
                if counts:
                    subclasses.append(name)
                    continue
                derived = False
                try:
                    # By the class's own parent, not only by name: `MSFT_UCScenarioControl` is a consumer class
                    # (Windows XP's "Microsoft WMI Updating Consumer Scenario Control") with no `EventConsumer` suffix.
                    derived = (
                        name in SUBSCRIPTION
                        or name.endswith("EventConsumer")
                        or cl.super_class_name == "__EventConsumer"
                    )
                except Exception:
                    pass
                if not derived:
                    continue
                try:
                    for inst in cl.instances:
                        if name == "__FilterToConsumerBinding":
                            print("%s\t%s\t%s -> %s" % (path, name, val(inst, "Filter"), val(inst, "Consumer")))
                        else:
                            print("%s\t%s\t%s" % (path, name, val(inst, "Name")))
                except Exception as e:
                    print("%s\t%s\tERR %r" % (path, name, e))
            if counts:
                total = 0
                for cl in ns.classes:
                    try:
                        total += sum(1 for _ in cl.instances)
                    except Exception:
                        pass
                print("%s\tclasses=%d\tinstances=%d" % (path, len(subclasses), total))


main()
