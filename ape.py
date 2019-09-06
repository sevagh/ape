#!/usr/bin/env python3.7

import signal
import sys
import time
import threading
import subprocess
import argparse
import os
import sys
import logging
from prometheus_client import start_http_server, Counter, Gauge


def compile_xdp_kern_prog(makerule, cflags):
    env = None
    if cflags:
        env = os.environ.copy()
        env["CFLAGS"] = "{0}".format(" ".join(cflags))

    logging.info(
        subprocess.check_output(
            "make kern_clean {0}".format(makerule), shell=True, env=env
        )
    )


def main():
    parser = argparse.ArgumentParser(description="ape - network chaos tool")

    parser.add_argument("device", type=str, help="iface to attach XDP to")
    parser.add_argument(
        "--udp-drop", dest="udp_drop", type=int, help="% of UDP packets to drop"
    )
    parser.add_argument(
        "--udp-port", dest="udp_port", type=int, help="UDP port to drop packets on"
    )

    parser.add_argument(
        "-d",
        "--debug",
        help="Print lots of debugging statements",
        action="store_const",
        dest="loglevel",
        const=logging.DEBUG,
        default=logging.WARNING,
    )
    parser.add_argument(
        "-v",
        "--verbose",
        help="Be verbose",
        action="store_const",
        dest="loglevel",
        const=logging.INFO,
    )

    ape_modules_metric = Gauge(
        "ape_loaded_xdp_progs",
        "XDP kernel programs loaded and attached by ape",
        ["interface", "name"],
    )

    args = parser.parse_args()
    logging.basicConfig(level=args.loglevel)

    run_drop = False
    unload_cmds = []

    if args.udp_drop:
        cflags = ["-DUDP_DROP_PROB={0}".format(args.udp_drop)]
        run_drop = True
        if args.udp_port:
            cflags.append("-DUDP_PORT={0}".format(args.udp_port))
        compile_xdp_kern_prog("kern_drop", cflags)

    if run_drop:
        print(
            subprocess.check_output(
                [
                    "./xdp_user_drop",
                    "--auto-mode",
                    "--dev",
                    args.device,
                    "--progsec",
                    "xdp_ape_drop",
                    "--filename",
                    "xdp_kern_drop.o",
                ]
            )
        )
        ape_modules_metric.labels(args.device, "xdp_ape_drop").set(1.0)
        unload_cmds.append(
            ["./xdp_user_drop", "--auto-mode", "--unload", "--dev", args.device]
        )

    def signal_handler(signal, frame):
        print("we got Ctrl-C")
        for u in unload_cmds:
            print(subprocess.check_output(u))
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    print("started prometheus metrics server at http://localhost:8000")
    start_http_server(8000)
    print("here")

    event = threading.Event()
    event.wait()

    return 0


if __name__ == "__main__":
    sys.exit(main())
