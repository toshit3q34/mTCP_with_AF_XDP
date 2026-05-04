#!/bin/bash
# disable_ht.sh — runtime SMT/HT disable, equivalent to BIOS HT-off for
# mTCP's purposes. Identifies hyperthread siblings from kernel topology
# and offlines the secondary thread on each physical core, leaving
# exactly one logical CPU per physical core online.
#
# Reverses on reboot. To make permanent, use `nosmt=force` on the kernel
# cmdline (see GRUB) — that is the actual BIOS-equivalent.
#
# Usage:
#   sudo ./disable_ht.sh           # offline all secondary HT siblings
#   sudo ./disable_ht.sh status    # show current online/offline state
#   sudo ./disable_ht.sh restore   # bring all CPUs back online
#
# Why mTCP cares: mTCP runs one thread per logical CPU you give it.
# If two of those land on HT siblings of the same physical core, they
# share the same set of execution units, L1/L2, and store buffer.
# Throughput collapses well below 2× one-thread perf because both
# threads spend most of their time stalled on each other.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Must run as root (writes to /sys/devices/system/cpu/cpuN/online)." >&2
    exit 1
fi

# Walk every CPU's thread_siblings_list. The list is comma-separated and
# the *first* entry is conventionally the "primary" sibling — keep that
# online, offline the rest. We dedupe so each physical core is touched
# only once.
collect_secondaries() {
    declare -A seen
    local secondaries=()
    for tsl in /sys/devices/system/cpu/cpu[0-9]*/topology/thread_siblings_list; do
        # Read e.g. "0,16" or "0-1"; expand ranges to a list.
        local raw
        raw=$(cat "$tsl")
        # Normalize "a-b" -> "a,a+1,...,b"
        local expanded=""
        IFS=',' read -ra parts <<< "$raw"
        for p in "${parts[@]}"; do
            if [[ "$p" == *-* ]]; then
                local lo=${p%-*} hi=${p#*-}
                for ((c=lo; c<=hi; c++)); do
                    expanded+="${c},"
                done
            else
                expanded+="${p},"
            fi
        done
        expanded=${expanded%,}
        # Skip if we've already processed this physical core
        local key="$expanded"
        [[ -n "${seen[$key]:-}" ]] && continue
        seen[$key]=1
        # Primary = first; rest are secondaries to offline
        IFS=',' read -ra siblings <<< "$expanded"
        for ((i=1; i<${#siblings[@]}; i++)); do
            secondaries+=("${siblings[i]}")
        done
    done
    printf '%s\n' "${secondaries[@]}"
}

cmd=${1:-disable}

case "$cmd" in
    status)
        echo "Logical CPUs online: $(nproc --all) physical, $(nproc) currently online"
        echo "Per-core thread layout:"
        lscpu -e=CPU,CORE,SOCKET,ONLINE | head -50
        ;;
    restore)
        echo "Bringing all CPUs back online..."
        for cpu in /sys/devices/system/cpu/cpu[0-9]*/online; do
            echo 1 > "$cpu" 2>/dev/null || true
        done
        echo "Done. nproc = $(nproc)"
        ;;
    disable|"")
        before=$(nproc)
        secondaries=($(collect_secondaries))
        echo "Online CPUs before: $before"
        echo "Will offline ${#secondaries[@]} secondary HT siblings: ${secondaries[*]}"
        for c in "${secondaries[@]}"; do
            # cpu0 cannot be offlined on most kernels — guard.
            if [[ "$c" == "0" ]]; then
                echo "  skipping cpu0 (kernel forbids offlining)"
                continue
            fi
            echo 0 > "/sys/devices/system/cpu/cpu${c}/online" || {
                echo "  WARN: failed to offline cpu${c}" >&2
            }
        done
        after=$(nproc)
        echo "Online CPUs after:  $after"
        echo
        echo "lscpu summary:"
        lscpu | grep -E 'Thread|Core|Socket|^CPU\(s\)'
        echo
        echo "NOTE: this resets on reboot. For a persistent (BIOS-equivalent)"
        echo "      change, add 'nosmt=force' to GRUB_CMDLINE_LINUX_DEFAULT"
        echo "      in /etc/default/grub, run update-grub, and reboot."
        ;;
    *)
        echo "Usage: $0 [disable|status|restore]" >&2
        exit 2
        ;;
esac
