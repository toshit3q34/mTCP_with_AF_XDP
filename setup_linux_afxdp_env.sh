#!/usr/bin/env bash

# RUN THIS IN THE ROOT DIRECTORY AND NOT HERE

set -e
echo "=== Updating system ==="
sudo apt update

echo "=== Installing base build tools ==="
sudo apt install -y build-essential git clang llvm gcc make pkg-config

echo "=== Installing bpftool ==="
sudo apt-get install -y linux-tools-$(uname -r) linux-tools-generic
ls /usr/lib/linux-tools/$(uname -r)/bpftool
sudo ln -sf /usr/lib/linux-tools/$(uname -r)/bpftool /usr/local/sbin/bpftool

echo "=== Installing required dev libraries ==="
sudo apt install -y libelf-dev zlib1g-dev libnuma-dev libpcap-dev libgmp-dev
sudo apt install -y m4 build-essential
sudo apt install autoconf

echo "=== Installing libbpf ==="
sudo apt install -y libbpf-dev

echo "=== Cloning and installing xdp-tools (libxdp) ==="
if [ ! -d "xdp-tools" ]; then
git clone https://github.com/xdp-project/xdp-tools.git
fi
cd xdp-tools
./configure
make -j$(nproc)
sudo make install
sudo ldconfig
cd ..

echo "=== Setting memlock limits (required for AF_XDP) ==="
USER_NAME=$(whoami)
if ! grep -q "$USER_NAME soft memlock unlimited" /etc/security/limits.conf; then
echo "$USER_NAME soft memlock unlimited" | sudo tee -a /etc/security/limits.conf
echo "$USER_NAME hard memlock unlimited" | sudo tee -a /etc/security/limits.conf
fi

echo "=== Ensuring PAM applies limits ==="
if ! grep -q "pam_limits.so" /etc/pam.d/common-session; then
echo "session required pam_limits.so" | sudo tee -a /etc/pam.d/common-session
fi
if ! grep -q "pam_limits.so" /etc/pam.d/common-session-noninteractive; then
echo "session required pam_limits.so" | sudo tee -a /etc/pam.d/common-session-noninteractive
fi

echo "=== Done ==="
echo "IMPORTANT: Reboot or relogin for memlock changes:"
echo " sudo reboot"