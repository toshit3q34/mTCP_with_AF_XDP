NUM_CORES=1
IFACE=<interface>

# 1. Force the indirection table to only use the first queue (Queue 0)
# This clears the "invalid argument" block
sudo ethtool -X "$IFACE" equal $NUM_CORES

# 2. Now you can safely reduce the combined channel count to 1
sudo ethtool -L "$IFACE" combined $NUM_CORES

# 3. Apply your hash settings and key
sudo ethtool -N "$IFACE" rx-flow-hash tcp4 sdfn
sudo ethtool -N "$IFACE" rx-flow-hash udp4 sdfn

sudo ethtool -X "$IFACE" hkey \
05:05:05:05:05:05:05:05:05:05:05:05:05:05:05:05:05:05:05:05:\
05:05:05:05:05:05:05:05:05:05:05:05:05:05:05:05:05:05:05:05:\
05:05:05:05:05:05:05:05:05:05:05:05