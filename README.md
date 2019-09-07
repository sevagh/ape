# ape - an XDP packet manipulation tool

Ape is a tool to manipulate UDP (both ipv4 and ipv6) packets.

The learning resources I used to create this project is https://github.com/xdp-project/xdp-tutorial (highly recommended if you want to get started with XDP). `headers/` and `common/` are copied from it.

### architecture

Ape looks stitched together, because it is. It consists of the following pieces:

1. Userspace XDP loaders, named `xdp_user_*.c` - these must be built **before** using ape, with `make clean all`
2. Kernel XDP programs, named `xdp_kern_*.c` - these are compiled at runtime by `ape.py` based on command-line arguments which are converted to `-D` compiler switches
3. `ape.py`, the main Python script and entrypoint of this project, which parses command-line arguments, builds and attaches the XDP kernel objects, and exposes XDP metrics to Prometheus using `bpftool`

`ape.py` must be run with sudo to execute privileged actions e.g. attaching XDP programs to NICs, but it drops privileges to `SUDO_UID` when compiling the kernel modules to not create root-owned files in the repository.

The maps intended for packet counts and stats are pinned using `bpffs`, and read using `bpftool`.

### drop

Drop UDP4/6 packets from an interface, with an optional port.

ape, dropping 50% of UDP packets on port 1337 on lo:
```
sevagh:ape $ sudo ./ape.py --udp-drop 50 --udp-port 1337 lo
b'Success: Loaded BPF-object(xdp_kern_drop.o) and used section(xdp_ape_drop)\n - XDP prog attached on device:lo(ifindex:1)\n - Unpinning (remove) prev maps in /sys/fs/bpf/lo/\n - Pinning maps in /sys/fs/bpf/lo/\n'
Starting bpftool map listener in thread
Started prometheus metrics server at http://localhost:8000
```

socat sender:
```
sevagh:~ $ for x in 1 2 3 4 5 6 7 8 9 10; do echo "hello world ${x}" | socat - UDP6-SENDTO:[::1]:1337; done
```

socat receiver:
```
sevagh:~ $ socat - UDP6-LISTEN:1337,bind=[::1],fork
hello world 1
hello world 2
hello world 4
hello world 5
hello world 7
hello world 9
hello world 10
```

We can see packets `3, 6, 8` missing. The Prometheus metrics show it, at `http://127.0.0.1:8000`:

```
ape_total_udp_packets{action="drop",device="lo",port="1337"} 10.0
# HELP ape_manipulated_udp_packets UDP packets manipulated by ape
# TYPE ape_manipulated_udp_packets gauge
ape_manipulated_udp_packets{action="drop",device="lo",port="1337"} 3.0
```

### scramble

Scramble UDP4/6 packets from an interface, with an optional port.

The implementation of scramble is much more complex than drop. There's no way to copy a packet, or "sleep", in XDP.

I need to use [`AF_XDP`](https://www.kernel.org/doc/html/latest/networking/af_xdp.html), which is a way to redirect packets from the XDP kernel program to userspace. Inside `xdp_user_scramble.c`, I set up UDP4 and UDP6 sender sockets. When the XDP kernel scramble program redirects a packet to the XSK map and I receive it in the user scramble program, I sleep randomly between 0-MAX_SLEEP_MS ms before re-sending it on the appropriate UDP4 or UDP6 socket. This results in packets seemingly being received out of order.

ape, scrambling 50% of UDP packets on port 1337 on lo:
```
sevagh:ape $ sudo ./ape.py --udp-scramble 50 --udp-port 1337 lo
sleeping 2s to let module load
Starting bpftool map listener in thread
Started prometheus metrics server at http://localhost:8000
```

socat sender:
```
sevagh:~ $ for x in 1 2 3 4 5 6 7 8 9 10; do echo "hello world ${x}" | socat - UDP6-SENDTO:[::1]:1337; done
```

socat receiver:
```
sevagh:~ $ socat - UDP6-LISTEN:1337,bind=[::1],fork
hello world 2
hello world 5
hello world 3
hello world 6
hello world 1
hello world 8
hello world 9
hello world 10
hello world 7
hello world 4
```

We can see the packets arrive out of order. The Prometheus metrics show it, at `http://127.0.0.1:8000`:

```
ape_total_udp_packets{action="scramble",device="lo",port="1337"} 18.0
# HELP ape_manipulated_udp_packets UDP packets manipulated by ape
# TYPE ape_manipulated_udp_packets gauge
ape_manipulated_udp_packets{action="scramble",device="lo",port="1337"} 8.0
```

There are more than 10 total packets, because `scramble` will feed back to itself (the XDP kernel program will probably re-scramble packets sent by the user scramble program).
