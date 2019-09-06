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
from struct import unpack
from binascii import unhexlify
from prometheus_client import start_http_server, Counter, Gauge
import datetime, threading


STOP_DROP_STATS = False


def drop_stats_output_reader(device, port, pinned_map_name, stats_interval_s, total_metric, manipulated_metric):
    total_pkts = subprocess.check_output(
            [
                'bpftool',
                '--bpffs',
                'map',
                'lookup',
                'pinned',
                pinned_map_name,
                'key',
                '1',
                '0',
                '0',
                '0'
            ])
    dropped_pkts = subprocess.check_output(
            [
                'bpftool',
                '--bpffs',
                'map',
                'lookup',
                'pinned',
                pinned_map_name,
                'key',
                '0',
                '0',
                '0',
                '0'
            ])
    total_packets = unpack('<2i', unhexlify(
        total_pkts.split(b'value:')[-1][1:-1].decode().replace(' ', '').encode('utf-8')
    ))[0]
    total_metric.labels(device, 'drop', port).set(total_packets)
    dropped_packets = unpack('<2i', unhexlify(
        dropped_pkts.split(b'value:')[-1][1:-1].decode().replace(' ', '').encode('utf-8')
    ))[0]
    manipulated_metric.labels(device, 'drop', port).set(dropped_packets)
    global STOP_DROP_STATS
    if not STOP_DROP_STATS:
        threading.Timer(stats_interval_s, drop_stats_output_reader, [device, port, pinned_map_name, stats_interval_s, total_metric, manipulated_metric]).start()
    else:
        print('Stopping drop stats thread')


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
    if os.geteuid() != 0:
        print(
            "Start {0} as root, it will drop privileges when compiling .o files".format(
                sys.argv[0]
            ),
            file=sys.stderr,
        )
        sys.exit(1)

    sudo_uid = int(os.getenv("SUDO_GID"))
    sudo_gid = int(os.getenv("SUDO_UID"))

    parser = argparse.ArgumentParser(description="ape - network chaos tool")

    parser.add_argument("device", type=str, help="iface to attach XDP to")
    parser.add_argument(
        "--udp-drop", dest="udp_drop", type=int, help="%% of UDP packets to drop"
    )
    parser.add_argument(
        "--udp-port", dest="udp_port", type=int, help="UDP port to drop packets on"
    )
    parser.add_argument(
        "--listen-port",
        dest="prom_port",
        type=int,
        help="HTTP port for Prometheus metrics endpoint",
        default=8000,
    )
    parser.add_argument(
        "--stats-interval-s",
        dest="stats_interval_s",
        type=int,
        help="Time in s to poll XDP maps and generate Prometheus metrics",
        default=1,
    )
    parser.add_argument(
        "-d",
        "--debug",
        help="debug out",
        action="store_const",
        dest="loglevel",
        const=logging.DEBUG,
        default=logging.WARNING,
    )
    parser.add_argument(
        "-v",
        "--verbose",
        help="verbose out",
        action="store_const",
        dest="loglevel",
        const=logging.INFO,
    )

    ape_modules_metric = Gauge(
        "ape_loaded_xdp_progs",
        "XDP kernel programs loaded and attached by ape",
        ["interface", "name"],
    )
    ape_total_metric = Gauge(
        "ape_total_udp_packets",
        "UDP packets intercepted by ape",
        ["device", "action", "port"]
    )
    ape_manipulated_metric = Gauge(
        "ape_manipulated_udp_packets",
        "UDP packets manipulated by ape",
        ["device", "action", "port"]
    )

    args = parser.parse_args()
    logging.basicConfig(level=args.loglevel)

    run_drop = False
    unload_cmds = []
    procs = []

    if args.udp_drop:
        cflags = ["-DUDP_DROP_PROB={0}".format(args.udp_drop)]
        run_drop = True
        if args.udp_port:
            cflags.append("-DUDP_PORT={0}".format(args.udp_port))
        else:
            args.udp_port = -1

        # drop privileges
        os.setresgid(sudo_gid, sudo_gid, -1)
        os.setresuid(sudo_uid, sudo_uid, -1)

        compile_xdp_kern_prog("kern_drop", cflags)

        # get them back
        os.setresgid(0, 0, -1)
        os.setresuid(0, 0, -1)

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

        print("Starting bpftool map listener in thread")
        drop_stats_output_reader(args.device, args.udp_port, '/sys/fs/bpf/{0}/drop_count'.format(args.device), args.stats_interval_s, ape_total_metric, ape_manipulated_metric)

    def signal_handler(signal, frame):
        global STOP_DROP_STATS
        STOP_DROP_STATS = True
        for u in unload_cmds:
            print(subprocess.check_output(u))
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    print("Started prometheus metrics server at http://localhost:8000")
    start_http_server(args.prom_port)

    event = threading.Event()
    event.wait()

    return 0


if __name__ == "__main__":
    sys.exit(main())
