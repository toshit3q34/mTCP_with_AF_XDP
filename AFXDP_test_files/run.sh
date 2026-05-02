# To install vmlinux.h
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h 

# To combine interface
sudo ip link set <interface> down
sudo ethtool -L <interface> combined 1
sudo ip link set <interface> up

# To compile XDP program
clang -O2 -g -target bpf -c xdp_kern.c -o xdp_kern.o

# To load XDP program on required interface
sudo ip link set dev <interface> xdp off    # Removes the previously loaded code
sudo ip link set dev <interface> xdpdrv obj xdp_kern.o sec xdp  # Can try xdpgeneric too

# To compile & run the AF_XDP user code
gcc xdp_rx.c -o xdp_rx -lbpf
sudo ./xdp_rx

# BPF Maps debugging & logging (bpf_printk) : Run on a second terminal
sudo cat /sys/kernel/debug/tracing/trace_pipe
