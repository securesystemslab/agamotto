#!/usr/bin/env python3

import argparse
import os
import re

import fuzz


def add_arguments(parser):
    parser.add_argument(
        "-i", "--input", dest="input",
        help="",
        required=True,
    )
    parser.add_argument(
        "-o", "--output", dest="output",
        help="",
        required=True,
    )
    parser.add_argument(
        "-t", "--host", dest="host",
        help="",
        default="localhost",
    )
    parser.add_argument(
        "-p", "--port", dest="port",
        help="",
        default=56841,
    )
    parser.add_argument(
        "-w", "--workdir", dest="workdir",
        help="",
        default="workdir",
    )
    parser.add_argument(
        "-c", "--vmcnt", dest="vmcnt",
        help="",
        default=1,
    )
    parser.add_argument(
        "-r", "--runid", dest="runid",
        help="",
        default=0,
    )


def parse_arguments(args):
    if not os.path.exists(args.input):
        raise Exception()

    if "GOPATH" not in os.environ:
        raise Exception()

    gopath = os.environ["GOPATH"]
    if not os.path.exists(gopath):
        raise Exception()

    cfg_name = os.path.basename(args.input)
    cfg = re.compile("^[^-]*-([^-]*)[-.].*$").search(cfg_name)
    cfg = cfg.group(1)

    cwd = os.getcwd()
    os.chdir(os.path.dirname(__file__))
    agents = fuzz.enumerate_guest_agents("linux")
    os.chdir(cwd)
    agent_id = agents.index("agent-%s-prog98" % (cfg))

    root_scripts = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(root_scripts)

    with open(args.input, "r") as infd:
        with open(args.output, "w") as outfd:
            outfd.truncate()
            for line in infd.readlines():
                line = line.replace("$AGPATH", root)
                line = line.replace("$WORKDIR", args.workdir)
                line = line.replace("$GOPATH", gopath)
                line = line.replace("$AGENTID", str(agent_id))
                line = line.replace("$HOST", args.host)
                line = line.replace("$PORT", args.port)
                line = line.replace("$VMCNT", str(args.vmcnt))
                line = line.replace("$RUNID", str(args.runid))
                outfd.write(line)


def main():
    parser = argparse.ArgumentParser()
    add_arguments(parser)
    args = parser.parse_args()
    parse_arguments(args)


if __name__ == "__main__":
    main()
