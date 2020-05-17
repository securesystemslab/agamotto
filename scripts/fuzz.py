#!/usr/bin/env python3

import argparse
import glob
import os
import multiprocessing
from multiprocessing import Process
import subprocess
import string
import threading
import re

TYPE_IO = 0x01
TYPE_MEMORY = 0x00

PCI_CLASS_NETWORK_ETHERNET = 0x0200
PCI_CLASS_NETWORK_OTHER = 0x0280
PCI_CLASS_WIRELESS_OTHER = 0x0d80
PCI_CLASS_OTHERS = 0xff

devices = {
    "aqc100": {
        "vendor": 0x1D6A,
        "device": 0x00B1,
        "revision": 0x0,
        "class": PCI_CLASS_NETWORK_ETHERNET,
        "mappings": [
            {"size": 0x10000, "type": TYPE_MEMORY},  # FIXME
        ],
        "image": "aqtion",
        "module": "drivers/net/ethernet/aquantia/atlantic/atlantic.ko",
    },
    "rtl8139": {
        "vendor": 0x10ec,
        "device": 0x8139,
        "revision": 0x20,
        "class": PCI_CLASS_NETWORK_ETHERNET,
        "subsystem_vendor": 0x0,
        "subsystem": 0x0,
        "mappings": [
            {"size": 0x100, "type": TYPE_IO},
            {"size": 0x100, "type": TYPE_MEMORY},
        ],
        "image": "rtl8139",
        "module": "drivers/net/ethernet/realtek/8139cp.ko",
    },
    "quark": {
        "vendor": 0x8086,
        "device": 0x937,
        "revision": 0x1,
        "class": PCI_CLASS_NETWORK_ETHERNET,
        "subsystem_vendor": 0x0,
        "subsystem": 0x0,
        "mappings": [
            {"size": 0x2000, "type": TYPE_MEMORY},
        ],
        "image": "stmmac",
        "module": "drivers/net/ethernet/stmicro/stmmac/stmmac-pci.ko",
    },
    "snic": {
        "vendor": 0x1137,
        "device": 0x0046,
        "revision": 0x1,
        "class": ~0,
        "subsystem_vendor": 0x0,
        "subsystem": 0x0,
        "mappings": [
            {"size": 0x4000, "type": TYPE_MEMORY},
            {"size": 0x4000, "type": TYPE_MEMORY},
            {"size": 0x4000, "type": TYPE_MEMORY},
        ],
        "image": "snic",
        "module": "drivers/scsi/snic/snic.ko",
    },
    "usb": {
        "image": "usb",
        "module": None,
    },
    "usb.rsi": {
        "image": "usb",
        "module": None,
    },
    "usb.mwifiex": {
        "image": "usb",
        "module": None,
    },
    "usb.ar5523": {
        "image": "usb",
        "module": None,
    },
    "usb.btusb": {
        "image": "usb",
        "module": None,
    },
    "usb.pn533": {
        "image": "usb",
        "module": None,
    },
    "usb.go7007": {
        "image": "usb",
        "module": None,
    },
    "usb.si470x": {
        "image": "usb",
        "module": None,
    },
    "usb.usx2y": {
        "image": "usb",
        "module": None,
    },
}

LINUX_BUILD_DIR = "../build/guest/linux"
WINDOWS_BUILD_DIR = "../build/guest/windows"

QEMU_RUN_SH = "run-qemu.sh"


def default_result_dir(dev, prog):
    # /scripts
    dirname = os.path.dirname(os.path.realpath("__file__"))
    # /
    dirname = os.path.dirname(dirname)
    # /results/<dev>/<prog>
    dirname = os.path.join(dirname, "results", dev, prog)

    return dirname


def default_drive_path(dev, prog):
    if dev not in devices:
        raise Exception("")

    dirname = default_result_dir(dev, prog)
    dirname = os.path.join(dirname, "overlay.qcow2")

    return os.path.abspath(dirname)


def default_kernel_dir(dev):
    if dev not in devices:
        raise Exception("")

    # /scripts
    dirname = os.path.dirname(os.path.realpath("__file__"))
    # /
    dirname = os.path.dirname(dirname)

    guestos = "linux"
    img = devices[dev]["image"]
    if not img:
        raise Exception("")

    # /build/guest/<OS>/image/<IMG>
    dirname = os.path.join(dirname, "build", "guest", guestos, "image", img)

    return dirname


def default_modules_dir(dev=""):
    # /scripts
    dirname = os.path.dirname(os.path.realpath("__file__"))
    # /
    dirname = os.path.dirname(dirname)

    guestos = "linux"

    # /build/guest/<OS>/image/modules
    dirname = os.path.join(dirname, "build", "guest",
                           guestos, "image", "modules")
    if dev in devices and "image" in devices[dev]:
        dirname = os.path.join(
            dirname,
            "lib",
            "modules",
            "4.19.0%s+" % devices[dev]["image"],  # TODO: glob
        )

    return dirname


def default_out_dir(dev, prog):
    if dev not in devices:
        raise Exception("")

    dirname = default_result_dir(dev, prog)

    if os.path.exists(dirname):
        return os.path.join(dirname, "out")

    dirname = "out-%s-%s" % (dev, prog)

    return dirname


def default_dict_dir(dev):
    if dev not in devices:
        raise Exception("")

    return "dictionary"


def io_desc(dev):
    if dev not in devices:
        raise Exception("")

    desc = list()
    for mapping in devices[dev]["mappings"]:
        if mapping["type"] == TYPE_MEMORY:
            desc.append("mmio=0x%x" % (mapping["size"]))
        if mapping["type"] == TYPE_IO:
            desc.append("io=0x%x" % (mapping["size"]))

    return ",".join(desc)


def run_qemu(kernel_dir, drive_path, dev, prog,
             in_dir=None, dict_dir=None, out_file=None,
             load_vm=None, sync_id=None, instance_id=0, root_only=False, master=False,
             exec_file=None, exec_virtual=False, no_restore=False,
             normal_qemu=False, corpus_paths=[], out_dir=None, stdout_file=None,
             gdb=False):
    os.chdir(os.path.abspath(os.path.dirname(QEMU_RUN_SH)))

    args = ["./%s" % (QEMU_RUN_SH)]

    if gdb:
        args.append("-GDB")

    serial_output_file = "serial.txt"
    if sync_id:
        if master:
            args.extend(["-M", sync_id])
        else:
            args.extend(["-S", sync_id])
        serial_output_file = "serial.%s.txt" % (sync_id)

    if kernel_dir == "windows":
        args.append("-w")
    else:
        args.extend(["-k", kernel_dir])

    if sync_id or not drive_path or not os.path.exists(drive_path):
        drive_path = os.path.abspath("stretch.img")
        if not os.path.exists(drive_path):
            raise Exception("%s not found. Please create one." % (drive_path))

    args.extend(["-d", drive_path])

    args.extend(["-p"])

    if out_file:
        args.extend(
            ["-F", os.path.join(default_result_dir(dev, prog), out_file)]
        )

    if exec_file and os.path.exists(exec_file):
        args.extend(["-x", os.path.abspath(exec_file)])

    if in_dir and os.path.exists(in_dir):
        args.extend(["-I", in_dir])

    if dict_dir and os.path.exists(dict_dir):
        args.extend(["-X", dict_dir])

    if out_dir and os.path.exists(out_dir):
        args.extend(["-O", out_dir])
    else:
        args.extend(["-O", default_out_dir(dev, prog)])

    if "vendor" in devices[dev]:
        args.extend(["-V", "0x%x" % devices[dev]["vendor"]])

        if exec_virtual:
            args.extend(["-D", dev])
        else:
            args.extend(["-D", "0x%x" % devices[dev]["device"]])
        args.extend(["-R", "0x%x" % devices[dev]["revision"]])
        args.extend(["-C", "0x%x" % devices[dev]["class"]])

    os_ = "linux"
    if kernel_dir == "windows":
        os_ = "windows"
    args.extend(["-G", "%d" % get_agent_id(os_, dev, prog)])

    # args.extend(["-IOMMU"])

    if os.path.exists("trace-events"):
        args.extend(["-t", "events=trace-events"])

    if "subsystem_vendor" in devices[dev]:
        args.extend(["-SV", "0x%x" % devices[dev]["subsystem_vendor"]])
    if "subsystem" in devices[dev]:
        args.extend(["-SD", "0x%x" % devices[dev]["subsystem"]])

    if "mappings" in devices[dev]:
        args.extend(["-IO", io_desc(dev)])

    if load_vm and load_vm != "":
        args.extend(["-l", load_vm])

    args.extend(["--seed", "%d" % instance_id])
    if root_only:
        args.extend(["--root-only"])

    if no_restore:
        args.extend(["--no-restore"])
    qemu_args = list()

    mem_path = os.path.join(default_result_dir(dev, prog), "mem")
    if sync_id:
        mem_path += ".%s" % sync_id

    qemu_args.extend([
        "-mem-path",
        mem_path
    ])
    qemu_args.extend([
        "-mem-prealloc",
    ])

    if prog == "debug":
        normal_qemu = True

    if not normal_qemu:
        args.extend(
            ["-f", os.path.join(default_result_dir(dev, prog),
                                serial_output_file)]
        )
    else:
        qemu_args.extend([
            "-serial", "stdio"
        ])

    if normal_qemu:
        args.extend(["-q"])

    if corpus_paths and len(corpus_paths) > 0:
        if len(corpus_paths) > 10:
            raise Exception("Too many corpus paths")
        args.extend(["-c", ",".join([os.path.abspath(p)
                                     for p in corpus_paths])])

    if sync_id:
        pid_file = os.path.join(
            default_result_dir(dev, prog),
            "vm.%s.pid" % (sync_id),
        )
    else:
        pid_file = os.path.join(
            default_result_dir(dev, prog),
            "vm.pid"
        )
    qemu_args.extend(["-pidfile", pid_file])

    if len(qemu_args) > 0:
        args.append("--")
        args.extend(qemu_args)

    cmd = " ".join(args)
    print(cmd)

    if stdout_file:
        proc = subprocess.Popen(
            args, cwd=os.path.abspath(os.path.dirname(QEMU_RUN_SH)),
            stdout=stdout_file
        )
    else:
        proc = subprocess.Popen(
            args, cwd=os.path.abspath(os.path.dirname(QEMU_RUN_SH))
        )

    try:
        proc.communicate()
    except KeyboardInterrupt:
        proc.kill()
        proc.wait()
        return

    if proc.wait() != 0:
        print("proc exited with errors.")


def check_dependencies():
    files_to_check = [QEMU_RUN_SH, "afl-whatsup"]
    for f in files_to_check:
        if not os.path.exists(f):
            raise Exception("File '%s' does not exist." % (f))


def check_linux_image(device, kernel_dir):
    if not os.path.exists(kernel_dir):
        raise Exception("'%s does not exist." % (kernel_dir))
    if not os.path.exists(os.path.join(kernel_dir, "vmlinux")):
        raise Exception("vmlinux not found.")

    bzImage = os.path.join(kernel_dir, "arch", "x86", "boot", "bzImage")
    if not os.path.exists(bzImage):
        raise Exception("bzImage not found.")

    image = device
    if "image" in devices[device]:
        image = devices[device]["image"]
    localversion = '[45]\.[0-9]+\.[0-9]+.*%s\+' % (image)
    prog = re.compile(localversion)

    dev_found = False
    strings = subprocess.getoutput("strings %s" % (bzImage)).split("\n")
    for line in strings:
        if prog.match(line):
            dev_found = True
            break

    if not dev_found:
        raise Exception("Unexpected bzImage: %s" % bzImage)


# Unique id for guest os
def get_agent_id(os_, dev, prog):
    agents = enumerate_guest_agents(os_)
    return agents.index("agent-%s-%s" % (dev, prog))


def enumerate_guest_agents(os_):
    agents = list()

    # needs to be consistent
    sorted_devs = sorted(devices.keys())
    sorted_devs = list(filter(
        lambda dev:
        "image" in devices[dev]
        and "module" in devices[dev],
        # and "mappings" in devices[dev]
        # and len(devices[dev]["mappings"]) > 0,
        sorted_devs
    ))
    sorted_progs = [prog.split("-")[1]
                    for prog in sorted(_enumerate_progs(os_))]

    for dev in sorted_devs:
        for prog in sorted_progs:
            agent = "agent-%s-%s" % (dev, prog)
            agents.append(agent)

    return agents


def _enumerate_progs(os_list):
    progs = list()

    if "linux" in os_list:
        progs.append("linux-debug")

        for prog in glob.glob("%s/progs/prog[0-9]*" % LINUX_BUILD_DIR):
            progs.append("linux-%s" % os.path.basename(prog))

        for prog in glob.glob("%s/traces/trace[0-9]*" % LINUX_BUILD_DIR):
            progs.append("linux-%s" % os.path.basename(prog))

    if "windows" in os_list:
        for prog in glob.glob("%s/progs/prog[0-9]*" % WINDOWS_BUILD_DIR):
            progs.append("windows-%s" % os.path.basename(prog))

        for prog in glob.glob("%s/traces/trace[0-9]*" % WINDOWS_BUILD_DIR):
            progs.append("windows-%s" % os.path.basename(prog))

    return progs


def add_arguments(parser):
    subparsers = parser.add_subparsers(dest="device")
    subparsers.required = True

    devparsers = list()
    for dev in devices:
        devparsers.append(subparsers.add_parser(dev))

    for devparser in devparsers:
        devparser.add_argument(
            "-g", '--guest-prog', type=str,
            choices=_enumerate_progs(["linux", "windows"]),
            help="",
            required=True,
        )
        devparser.add_argument(
            "-w", "--windows", action="store_true",
            help="",
        )
        devparser.add_argument(
            "-k", "--kernel", dest="kernel_dir",
            help="",
        )
        devparser.add_argument(
            "-d", "--drive", dest="drive_path",
            help="",
        )
        devparser.add_argument(
            "-N", "--num-instances", dest="num_instances",
            type=int,
            help="",
        )
        devparser.add_argument(
            "-l", "--loadvm", dest="vm_image",
            help="",
        )
        devparser.add_argument(
            "-i", "--in-dir", dest="in_dir",
            help="",
        )
        devparser.add_argument(
            "-o", "--out-dir", dest="out_dir",
            help="",
        )
        devparser.add_argument(
            "-ro", "--root-only", dest="root_only", action="store_true",
            help="only store root checkpoint"
        )
        devparser.add_argument(
            "-nr", "--no-restore", dest="no_restore", action="store_true",
            help="disable checkpoint restore (for baseline testing)"
        )
        devparser.add_argument(
            "-x", "--exec", dest="input_to_exec",
            help="run guest with a replay device, no fuzzing",
        )
        devparser.add_argument(
            "-xv", "--exec-virtual", action="store_true",
            help="run guest with a virtual device, no fuzzing",
        )
        devparser.add_argument(
            "-X", "--dict-dir", dest="dict_dir",
            help=""
        )
        devparser.add_argument(
            "-q", "--normal-qemu", dest="normal_qemu", action="store_true",
            help="run guest, no fuzzing"
        )
        devparser.add_argument(
            "-c", "--coverage", dest="corpus_path",
            nargs="+",
            help="A list of corpus dirs/files to collect coverage for.",
        )
        devparser.add_argument(
            "-G", "--gdb", action="store_true",
            help="",
        )


def parse_arguments(args):
    if "windows" in args and args.windows:
        if args.kernel_dir:
            raise Exception("--windows and --kernel are mutually exclusive.")
        kernel_dir = "windows"
    else:  # Linux
        kernel_dir = args.kernel_dir
        if not kernel_dir:
            kernel_dir = default_kernel_dir(args.device)
        check_linux_image(args.device, kernel_dir)

    guest_prog = ""
    if args.guest_prog:
        guest_prog = args.guest_prog.split("-")[1]

    drive_path = args.drive_path
    # if not args.drive_path:
    #    drive_path = default_drive_path(args.device, guest_prog)

    if drive_path and not os.path.exists(drive_path):
        raise Exception("%s does not exist." % (drive_path))

    dict_dir = args.dict_dir
    # if not args.dict_dir:
    #    dict_dir = default_dict_dir(args.device)

    if args.num_instances and args.num_instances > 1:
        for ignored in ["corpus_path", "normal_qemu", "input_to_exec", "exec_virtual"]:
            if getattr(args, ignored):
                print("Ignoring %s: %s" % (ignored, getattr(args, ignored)))

        cpu_count = multiprocessing.cpu_count()
        cpu_count = min(100, cpu_count)
        if cpu_count <= 1:
            raise Exception("No multiple CPUs found.")

        num_instances = args.num_instances

        sync_ids = ["fuzzer%02d-M" % 0]
        for i in range(1, num_instances):
            sync_ids.append("fuzzer%02d-S" % (i))

        out_files = list()
        for i in range(0, num_instances):
            out_files.append("cur%02d" % (i))

        threads = list()
        for i in range(0, num_instances):
            master = False
            if i == 0:
                master = True
            thread = threading.Thread(
                target=run_qemu,
                kwargs={
                    "kernel_dir": kernel_dir,
                    "drive_path": drive_path,
                    "dev": args.device,
                    "prog": guest_prog,
                    "load_vm": args.vm_image,
                    "in_dir": args.in_dir,
                    "dict_dir": dict_dir,
                    "out_dir": args.out_dir,
                    "out_file": out_files[i],
                    "sync_id": sync_ids[i],
                    "instance_id": i,
                    "root_only": args.root_only,
                    "no_restore": args.no_restore,
                    "master": master,
                },
            )
            threads.append(thread)

        try:
            for thread in threads:
                thread.start()

        except KeyboardInterrupt:
            print("TODO: Handling Ctrl+C")

    else:
        run_qemu(
            kernel_dir=kernel_dir,
            drive_path=drive_path,
            dev=args.device,
            prog=guest_prog,
            in_dir=args.in_dir,
            dict_dir=dict_dir,
            out_file="cur",
            out_dir=args.out_dir,
            load_vm=args.vm_image,
            exec_file=args.input_to_exec,
            exec_virtual=args.exec_virtual,
            normal_qemu=args.normal_qemu,
            corpus_paths=args.corpus_path,
            instance_id=0,
            root_only=args.root_only,
            no_restore=args.no_restore,
            gdb=args.gdb,
        )


def main():
    check_dependencies()
    parser = argparse.ArgumentParser()
    add_arguments(parser)
    args = parser.parse_args()
    parse_arguments(args)


if __name__ == "__main__":
    main()
