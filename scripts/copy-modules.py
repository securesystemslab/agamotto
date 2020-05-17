#!/usr/bin/env python3

import argparse
from string import Template
import os
import fuzz
import subprocess


devices = fuzz.devices


LINUX_AGENT_TMPL_SH = "../guest/linux/agents/agent.sh"
LINUX_AGENT_SH = "../guest/linux/agents/generated/agent.sh"
LINUX_AGENT_DEV_TMPL_SH = "../guest/linux/agents/agent-dev-prog.sh"
LINUX_AGENT_DEV_DEBUG_TMPL_SH = "../guest/linux/agents/agent-dev-debug.sh"
LINUX_AGENT_DEV_SH = "../guest/linux/agents/generated/agent-${dev}-${prog}.sh"


def get_executable_path(os_, prog):
    prog_dir = ""
    if os_ == "linux":
        prog_dir = fuzz.LINUX_BUILD_DIR
    elif os_ == "windows":
        prog_dir = fuzz.WINDOWS_BUILD_DIR
    else:
        raise Exception("unknown OS %s" % (os_))

    if prog.startswith("prog"):
        prog_dir = os.path.join(prog_dir, "progs")
    elif prog.startswith("trace"):
        prog_dir = os.path.join(prog_dir, "traces")
    else:
        raise Exception("unknown type %s" % (prog))

    return os.path.join(prog_dir, prog)


def setup_blacklist(os_):
    if os_ != "linux":
        return
    blacklist = "%s/blacklist.conf" % fuzz.LINUX_BUILD_DIR
    with open(blacklist, "w") as fd:
        for dev in devices:
            if "module" not in devices[dev] or not devices[dev]["module"]:
                continue
            module_ko = os.path.basename(devices[dev]["module"])
            module_noext = os.path.splitext(module_ko)[0]
            fd.write("blacklist %s\n" % module_noext)


def setup_guest_agent(os_):
    generated_dir = "../guest/linux/agents/generated"

    if not os.path.exists(generated_dir):
        os.mkdir(generated_dir)

    all_agents = fuzz.enumerate_guest_agents(os_)

    with open(LINUX_AGENT_TMPL_SH, "r") as f_in:
        with open(LINUX_AGENT_SH, "w") as f_out:
            sh = Template(f_in.read()).substitute(
                AGENTS="\n    ".join(
                    ["\"%s.sh\" # %d" % (a, all_agents.index(a)) for a in all_agents]),
            )
            f_out.write(sh)

    for agent in all_agents:
        (_, dev, prog) = agent.split("-")

        if "image" not in devices[dev]:
            continue

        if "module" not in devices[dev]:
            continue

        agent = Template(LINUX_AGENT_DEV_SH).substitute(
            dev=dev,
            prog=prog,
        )

        with open(LINUX_AGENT_DEV_TMPL_SH, "r") as f_in, open(agent, "w") as f_out:
            sh = Template(f_in.read()).substitute(
                image=devices[dev]["image"],
                skip_root_chkpt="true" if prog.endswith(
                    "debug") or prog == "prog99" or prog == "prog98" or prog == "prog80" or prog == "prog81" \
                               else "false",
                skip_modprobe="false" if devices[dev]["module"] and not (prog == "prog80" or prog == "prog81" ) \
                               else "true",
                module=os.path.basename(
                    devices[dev]["module"]).split(".")[0] if devices[dev]["module"] else "",
                module_relpath=devices[dev]["module"] if devices[dev]["module"] else "",
                prog=prog,
            )
            f_out.write(sh)


def copy_modules(mod, img, script):
    args = list()

    args = ["./%s" % ("copy-modules.sh")]
    args.append(mod)
    args.append(img)
    args.append(script)

    proc = subprocess.Popen(
        args, cwd=os.path.abspath(os.path.dirname("copy-modules.sh")))

    proc.communicate()

    if proc.wait() != 0:
        raise Exception("proc exited with errors.")


def add_arguments(parser):
    subparsers = parser.add_subparsers(dest="device")
    subparsers.required = True

    devparsers = list()

    devparsers.append(subparsers.add_parser("all"))

    for dev in devices:
        devparsers.append(subparsers.add_parser(dev))

    for devparser in devparsers:
        devparser.add_argument(
            "-m", "--modules-dir", dest="modules_dir",
            help="default: %s" % (fuzz.default_modules_dir()),
        )
        devparser.add_argument(
            "-d", "--drive-image-path", dest="img_path",
            help="",
            required=True,
        )


def parse_arguments(args):
    modules_dir = args.modules_dir
    if not modules_dir:
        modules_dir = fuzz.default_modules_dir()

    if not os.path.exists(modules_dir):
        raise Exception("%s does not exist." % (modules_dir))
    if not os.path.exists(args.img_path):
        raise Exception("%s does not exist." % (args.img_path))

    devs = list()
    if args.device == "all":
        devs.extend(devices.keys())
    else:
        devs.append(args.device)

    setup_guest_agent("linux")
    setup_blacklist("linux")

    copy_modules(modules_dir, args.img_path, LINUX_AGENT_SH)


def check_dependencies():
    files_to_check = [
        "copy-modules.sh",
        LINUX_AGENT_TMPL_SH,
        LINUX_AGENT_DEV_TMPL_SH,
    ]
    for f in files_to_check:
        if not os.path.exists(f):
            raise Exception("File '%s' does not exist." % (f))


def main():
    check_dependencies()
    parser = argparse.ArgumentParser()
    add_arguments(parser)
    args = parser.parse_args()
    parse_arguments(args)


if __name__ == "__main__":
    main()
