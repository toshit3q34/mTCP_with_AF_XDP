NUM_CORES=4
IFACE=enp65s0f0np0

# Match DPDK's rss_hf — hash on src/dst IP + src/dst port for TCP and UDP
sudo ethtool -N "$IFACE" rx-flow-hash tcp4 sdfn
sudo ethtool -N "$IFACE" rx-flow-hash udp4 sdfn

# Match DPDK's symmetric key (all 0x05)
sudo ethtool -X "$IFACE" hkey \
05:05:05:05:05:05:05:05:05:05:05:05:05:05:05:05:05:05:05:05:\
05:05:05:05:05:05:05:05:05:05:05:05:05:05:05:05:05:05:05:05

# Same number of RX queues as you have mTCP cores, evenly spread
sudo ethtool -L "$IFACE" combined $NUM_CORES
sudo ethtool -X "$IFACE" equal $NUM_CORES