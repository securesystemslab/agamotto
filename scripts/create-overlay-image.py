#!/usr/bin/env python3

import argparse
import fuzz
import os
import subprocess


devices = fuzz.devices


def default_results_dir():
    # /scripts
    dirname = os.path.dirname(os.path.realpath(__file__))
    # /
    dirname = os.path.dirname(dirname)

    # /results
    dirname = os.path.join(dirname, "results")

    return os.path.abspath(dirname)


def create_overlay_image(img_path, overlay_img_path):
    args = list()

    args = ["./%s" % ("create-overlay-image.sh")]
    args.append(img_path)
    args.append(overlay_img_path)

    proc = subprocess.Popen(
        args, cwd=os.path.abspath(os.path.dirname("create-overlay-image.sh")))

    proc.communicate()

    if proc.wait() != 0:
        print("proc exited with errors.")


def _check_dependencies():
    files_to_check = [
        "create-overlay-image.sh",
    ]
    for f in files_to_check:
        if not os.path.exists(f):
            raise Exception("File '%s' does not exist." % (f))
    return


def add_arguments(parser):
    subparsers = parser.add_subparsers(dest="device")
    subparsers.required = True

    devparsers = list()
    devparsers.append(subparsers.add_parser("all"))
    devparsers.append(subparsers.add_parser("usb%"))

    for dev in devices:
        devparsers.append(subparsers.add_parser(dev))

    for devparser in devparsers:
        devparser.add_argument(
            "-d", "--drive-image-path", dest="img_path",
            help="",
            required=True,
        )
        devparser.add_argument(
            "-f", "--force", action="store_true",
            help="",
        )


def parse_arguments(args):
    if args.device == "all":
        devs = devices.keys()
    elif args.device == "usb%":
        devs = list(filter(lambda dev: dev.startswith("usb"), devices.keys()))
    else:
        devs = [args.device]

    devs = sorted(devs)

    img_path = os.path.abspath(args.img_path)

    os_ = "linux"

    for agent in fuzz.enumerate_guest_agents(os_):
        (_, dev, prog) = agent.split("-")
        if dev not in devs:
            continue

        overlay_img_dir = os.path.join(
            default_results_dir(), dev, prog)
        os.makedirs(overlay_img_dir, exist_ok=True)

        # overlay_img = "%s.qcow2" % (os.path.basename(img_path))
        overlay_img = "overlay.qcow2"
        overlay_img_path = os.path.join(overlay_img_dir, overlay_img)

        if args.force and os.path.exists(overlay_img_path):
            os.remove(overlay_img_path)

        print(overlay_img_path)

        create_overlay_image(img_path, overlay_img_path)


def main():
    _check_dependencies()
    parser = argparse.ArgumentParser()
    add_arguments(parser)
    args = parser.parse_args()
    parse_arguments(args)


if __name__ == "__main__":
    main()
