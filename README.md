# mTCP with AF_XDP

This project adds an AF_XDP I/O backend to [mTCP](https://github.com/mtcp-stack/mtcp/), alongside the existing DPDK / netmap / PSIO / ONVM modules. mTCP is a user space networking stack and was also
featured in NSDI'14.

The goal of the project is to run mTCP on stock
Linux kernels (5.x+) with no proprietary userspace driver - using AF_XDP
sockets with a custom XDP program for packet steering.

The project was tested on [CloudLab](https://cloudlab.us) which provides free access
to bare-metal servers to researches. Special thanks to them!

## Table of contents

1. [What is AF_XDP?](#what-is-af_xdp)
2. [What's new](#whats-new)
   - [New source files](#new-source-files)
   - [Touch-ups in shared mTCP code](#touch-ups-in-shared-mtcp-code)
   - [Build-system changes](#build-system-changes)
3. [How the AF_XDP path works](#how-the-af_xdp-path-works)
4. [Things to know about the frame-key mapping & to take care of](#things-to-know-about-the-frame-key-mapping--to-take-care-of)
5. [Build](#build)
6. [Run](#run)
7. [Known limitations and future work](#known-limitations-and-future-work)

## What is AF_XDP?

**AF_XDP** is a Linux socket family (introduced in kernel 4.18, mature
in 5.x) that delivers raw packet frames to and from userspace with
near-DPDK throughput, while keeping the NIC under the kernel's normal
control. Unlike DPDK, it does not require a userspace driver, hugepages,
or unbinding the NIC from the kernel.

The pieces that matter:

- **XDP (eXpress Data Path)** — a hook in the kernel network stack that
  runs an eBPF program on every received packet *before* an `sk_buff`
  is allocated. The program returns one of `XDP_PASS` (let the kernel
  handle it normally), `XDP_DROP`, `XDP_TX`, or `XDP_REDIRECT`.
- **AF_XDP socket (xsk)** — a Linux socket bound to a specific (NIC,
  RX queue) pair. When XDP returns `XDP_REDIRECT` into a special map
  (`BPF_MAP_TYPE_XSKMAP`), the packet lands in this socket's userspace
  ring instead of the kernel's stack.
- **UMEM** — a chunk of userspace memory, registered with the kernel,
  that backs all the rings. The kernel writes incoming packets into
  it and userspace reads them in place; userspace also writes outgoing
  packets into it for the kernel to send.
- **Four rings per socket** —
  - **RX**: kernel produces, userspace consumes (incoming packets).
  - **TX**: userspace produces, kernel consumes (outgoing packets).
  - **FQ (Fill Queue)**: userspace gives the kernel free UMEM frames
    to write incoming packets into.
  - **CQ (Completion Queue)**: kernel returns UMEM frames to userspace
    after TX is done so they can be reused.

In this project the XDP program (`afxdp_kern.c`) decides on a per-packet
basis whether to forward to mTCP via `XDP_REDIRECT` or leave the packet
to the kernel via `XDP_PASS`, and the userspace half (`afxdp_module.c`)
manages the UMEM, rings, and the `xsks_map` so mTCP's main loop can pull
packets off as if it were a userspace driver.

You can see the directory `AFXDP_test_files` to get an idea about how to write
an eBPF-XDP code and a userspace AF_XDP socket. It consists of different versions which were used
by me to learn, understand and test.

## What's new

### New source files

- `mtcp/src/afxdp_kern.c` — the in-kernel XDP/eBPF program. Decides
  per-packet whether to redirect into an AF_XDP socket or pass to the
  Linux kernel stack.
- `mtcp/src/afxdp_module.c` — the userspace half. Implements mTCP's
  `io_module_func` interface (`load_module`, `init_handle`, `recv_pkts`,
  `get_rptr`, `send_pkts`, `get_wptr`, `release_pkt`, `destroy_handle`,
  `dev_ioctl`) on top of `libxdp` AF_XDP sockets.

### Touch-ups in shared mTCP code

- `mtcp/src/io_module.c` — interface enumeration path for `io = afxdp`,
  populates `CONFIG.eths[]` and `devices_attached[]` from the OS.
- A sample config is provided at `apps/example/epserver_afxdp.conf`.
- An environment build script is provided at `setup_linux_afxdp_env.sh`.

### Build-system changes

- `configure.ac` —
  - New `--enable-afxdp` flag.
  - New `AFXDP` substitution variable (defaults to 0; set to 1 when
    `--enable-afxdp` is passed).
  - The "no I/O lib selected" check now also recognises `afxdp` as a
    valid choice.
- `mtcp/src/Makefile.in` —
  - New `AFXDP=@AFXDP@` substitution.
  - `afxdp_module.c` added to `SRCS`.
  - When `AFXDP=1`: links against `-lxdp -lbpf -lelf -lz`, defines
    `AFXDP_KERN_PATH` so the userspace knows where to find the
    compiled BPF object. When `AFXDP=0`: defines `-DDISABLE_AFXDP`,
    leaving the source compiled out.
  - New `BPF_CLANG` / `BPF_CFLAGS` variables and an explicit rule for
    `afxdp_kern.o` (built with `clang -target bpf -O2 -g`).
  - When `AFXDP=1`, `afxdp_kern.o` is added to the default `all` goal.
  - `AFXDP_KERN_PATH` is overridable from the command line:
    `make AFXDP_KERN_PATH=/abs/path/afxdp_kern.o`.
- `apps/example/Makefile.in` — example app's `LIBS` line picks up
  `-lxdp -lbpf -lelf -lz` so the linker can resolve the new symbols
  in `libmtcp.a`.

## How the AF_XDP path works

```
NIC ──→ XDP (afxdp_kern.c)
        │
        ├── SSH / unmatched     →  XDP_PASS  →  kernel stack (SSH, gateway)
        │
        └── everything else              →  bpf_redirect_map(xsks_map[key]) → AF_XDP socket
                                                                   │
                                                                   ▼
                                  userspace UMEM ring  ── recv_pkts() / get_rptr() ──→ mTCP
                                          ▲                                              │
                                          │                                              ▼
                                          └── send_pkts() / get_wptr() ──── TX path ── ProcessPacket
```

Key design points:

- One `xsks_map` (BPF_MAP_TYPE_XSKMAP) shared between all attached
  interfaces. The userspace inserts each AF_XDP socket fd into the map
  at a key matching how the kernel program looks it up.
- The XDP program runs on every iface that mTCP claims; kernel keeps
  ownership of any iface mTCP isn't bound to.
- There is shared UMEM per core, which is shared among multiple AF_XDP
  sockets. Thus, we have 1 socket for each interface per core.
- One UMEM per mTCP thread, shared across all sockets that thread owns.
  16384 frames of `XSK_UMEM__DEFAULT_FRAME_SIZE` each. FQ pre-filled
  with 4096 frames at init.

## Things to know about the frame-key mapping & to take care of

This is the part that took the most iteration to get right.

- The kernel-side BPF program currently keys `xsks_map` by
  `ctx->rx_queue_index`, and the userspace inserts at key = `queue_id`.
  This works for the intended single-data-iface, single-queue setup.
- A multi-NIC setup where each NIC has only queue 0 will have all
  sockets land at `xsks_map[0]` and collide — last write wins. If you
  ever add more than one data interface, switch back to keying on
  `ctx->ingress_ifindex` and `bpf_map_update_elem(..., &kernel_ifindex, ...)`
  on the userspace side. The kern file's header comment documents this
  limitation.
- TCP traffic on port 22 is unconditionally XDP_PASSed so SSH always
  reaches the kernel, regardless of which iface it arrives on. This is to prevent
  it from interfering with the testing interface of CloudLab.

## Build

Before starting to build the file, it is recommended that the script
`setup_linux_afxdp_env.sh` is ran in the root directory regardless of the version/distro.
This sets up the environment and resolves all dependencies.
You can also see that the script makes `vmlinux.h` using `bpftool` in the `mtcp/src/` directory.
This is used for resolving incomplete function definitions.

```bash
# Clone the script & run
git clone https://github.com/toshit3q34/mTCP_with_AF_XDP/blob/master/setup_linux_afxdp_env.sh
chmod +x setup_linux_afxdp_env.sh
./setup_linux_afxdp_env.sh
```

The standard mTCP build picks the backend from `Makefile.in` and the
config flag. The makefile builds the BPF object alongside the userspace lib.

```bash
# Make the whole mTCP repository
cd ~/mtcp
autoreconf -fi
./configure --enable-afxdp
make
```

The userspace looks up `afxdp_kern.o` via the env var `AFXDP_KERN_PATH` so configure it.

```bash
export AFXDP_KERN_PATH=../../mtcp/src/afxdp_kern.o
```

## Run

Currently the run has only been done for a single interface. For testing you can merge queues
using `ethtool -L combine`.

```bash
# Single data interface (recommended for now):
cd apps/example
# Make www directory with an index.html (or whatever works for you)
sudo ./epserver -p ./www -f epserver_afxdp.conf -N 1
```

`epserver_afxdp.conf` should set `io = afxdp` and `port = <data_iface>`
(e.g. `port = eno1d1`). Keeping the management interface out of the
port list lets the kernel keep handling SSH normally — the XDP program
won't even be attached there.

ARP entries can be added statically to `config/arp.conf` or can also be dynamically resolved.
You can see how to add ARP entries in the mTCP documentation.

For debugging and viewing map logs (which uses BPF_PRINTK) you can run this in second terminal:
```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

## Known limitations and future work

- **Single queue per NIC assumed.** Multi-queue + multi-NIC needs
  composite keying (`(ifindex, queue_id)`) in both kern and userspace.
- **SKB mode XDP only.** Native (driver) mode wasn't required for
  mlx4_en CloudLab nodes; for higher-throughput drivers, switching the
  attach mode to `XDP_MODE_NATIVE` should be straightforward.
- **No addition of RSS manually** We assume that per flow RSS is a characteristic of
  NIC and need not be added manually. This can easily be done by configuring the NIC
  using `ethtool` before starting the run.
- **No hardware checksum offload.** `afxdp_dev_ioctl` returns -1, so
  mTCP falls back to software checksum verification on RX and software
  checksum generation on TX. This is correct but slower.
