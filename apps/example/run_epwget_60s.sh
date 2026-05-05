#!/bin/bash
# run_epwget_60s.sh
# ------------------------------------------------------------------
# Run epwget against a fixed target for a fixed wall-clock window
# (default 60s), gracefully stop it with SIGINT so the cumulative
# stats printer in epwget.c (PrintFinalStats) fires, then report
# the NIC-level RX/TX delta across the run.
#
# AF_XDP note: packets that XDP redirects into AF_XDP sockets do
# NOT increment /proc/net/dev counters (those reflect what the
# kernel stack saw). Driver-level counters from ethtool -S DO see
# AF_XDP traffic, so we snapshot both and prefer ethtool when
# present.
#
# Defaults match what you asked for:
#   sudo ./epwget 10.10.1.1/index.html 10000000 -N 16 -f epwget.conf
#
# Override via env vars:
#   sudo DURATION=120 N=8 IFACE=ens1f1 ./run_epwget_60s.sh
#   sudo TARGET=10.10.1.1/test.txt CONF=mywget.conf ./run_epwget_60s.sh
# ------------------------------------------------------------------

set -uo pipefail

DURATION=${DURATION:-60}
TARGET=${TARGET:-10.10.1.1/index.html}
TOTAL_REQS=${TOTAL_REQS:-10000000}
N=${N:-16}
CONF=${CONF:-epwget.conf}
LOG=${LOG:-/tmp/epwget_run_$(date +%Y%m%d_%H%M%S).log}
GRACE_SECS=${GRACE_SECS:-15}

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: run as root (epwget needs CAP_NET_ADMIN for AF_XDP)." >&2
    exit 1
fi

# cd to the script's own directory so ./epwget and ./<conf> resolve.
cd "$(dirname "$0")"

if [[ ! -x ./epwget ]]; then
    echo "ERROR: ./epwget not found or not executable in $(pwd)" >&2
    exit 1
fi
if [[ ! -f "$CONF" ]]; then
    echo "ERROR: config '$CONF' not found in $(pwd)" >&2
    exit 1
fi

# Auto-detect iface from `port = ` line in the config (unless overridden).
if [[ -z "${IFACE:-}" ]]; then
    IFACE=$(awk -F= '/^[[:space:]]*port[[:space:]]*=/ {
        gsub(/[[:space:]#].*$/,"",$2); gsub(/[[:space:]]/,"",$2);
        if ($2 != "") { print $2; exit }
    }' "$CONF")
fi
if [[ -z "${IFACE:-}" ]]; then
    echo "ERROR: could not auto-detect iface from $CONF; set IFACE=<name> manually." >&2
    exit 2
fi

# /proc/net/dev snapshot. Returns: rx_bytes rx_pkts rx_errs rx_drops tx_bytes tx_pkts tx_errs tx_drops
proc_counters() {
    awk -v IF="$1" '
        $1 ~ "^"IF":" {
            gsub(/:/,"",$1)
            print $2, $3, $4, $5, $10, $11, $12, $13
            exit
        }' /proc/net/dev
}

# ethtool -S snapshot. We capture every line so the delta routine can
# diff arbitrary key=value pairs (driver counter names vary by NIC).
ethtool_counters() {
    if command -v ethtool >/dev/null 2>&1; then
        ethtool -S "$1" 2>/dev/null | awk 'NR>1 {gsub(/:/,"",$1); print $1" "$NF}' | sort
    fi
}

# Print delta between two ethtool snapshots, filtering to interesting keys.
ethtool_delta() {
    local before_file=$1 after_file=$2
    if [[ ! -s "$before_file" || ! -s "$after_file" ]]; then
        return
    fi
    join -j1 "$before_file" "$after_file" \
        | awk '{ delta = $3 - $2; if (delta != 0) printf "  %-40s %15d\n", $1, delta }' \
        | grep -Ei 'rx_packets|tx_packets|rx_bytes|tx_bytes|rx_dropped|tx_dropped|rx_missed|rx_errors|tx_errors|rx_no_buffer|alloc_fail|xdp|xsk' \
        || true
}

# ---------- snapshot before ----------
before_proc=$(proc_counters "$IFACE")
if [[ -z "$before_proc" ]]; then
    echo "ERROR: iface '$IFACE' not present in /proc/net/dev." >&2
    awk -F: 'NR>2 {gsub(/ /,"",$1); print "  available: "$1}' /proc/net/dev >&2
    exit 2
fi
read -r RX_B0 RX_P0 RX_E0 RX_D0 TX_B0 TX_P0 TX_E0 TX_D0 <<< "$before_proc"

before_ethtool=$(mktemp)
after_ethtool=$(mktemp)
ethtool_counters "$IFACE" > "$before_ethtool"

cat <<EOF
==> iface       : $IFACE
==> target      : $TARGET
==> conf        : $CONF
==> cores (-N)  : $N
==> total reqs  : $TOTAL_REQS
==> duration    : ${DURATION}s
==> log         : $LOG

EOF

# ---------- launch epwget in its own session so we can SIGINT it cleanly ----------
setsid ./epwget "$TARGET" "$TOTAL_REQS" -N "$N" -f "$CONF" \
    > "$LOG" 2>&1 < /dev/null &
PID=$!
echo "==> epwget PID=$PID, running for ${DURATION}s..."

# Wait DURATION seconds, exit early if process dies.
START_EPOCH=$(date +%s)
SECS=0
while (( SECS < DURATION )); do
    if ! kill -0 "$PID" 2>/dev/null; then
        echo "==> epwget exited early after ${SECS}s (see $LOG)." >&2
        break
    fi
    sleep 1
    SECS=$(( $(date +%s) - START_EPOCH ))
done

# ---------- graceful shutdown via SIGINT ----------
if kill -0 "$PID" 2>/dev/null; then
    echo "==> sending SIGINT to PID $PID for graceful shutdown..."
    kill -INT "$PID" 2>/dev/null || true

    # Allow up to GRACE_SECS for threads to drain + PrintFinalStats to fire.
    GRACE=0
    while (( GRACE < GRACE_SECS )); do
        if ! kill -0 "$PID" 2>/dev/null; then break; fi
        sleep 1
        ((GRACE++)) || true
    done

    if kill -0 "$PID" 2>/dev/null; then
        echo "==> still alive after ${GRACE_SECS}s; escalating SIGTERM..."
        kill -TERM "$PID" 2>/dev/null || true
        sleep 2
        kill -KILL "$PID" 2>/dev/null || true
    fi
fi
wait "$PID" 2>/dev/null || true
END_EPOCH=$(date +%s)
ELAPSED=$(( END_EPOCH - START_EPOCH ))
echo "==> epwget stopped (wall-clock ~${ELAPSED}s)."

# ---------- snapshot after ----------
after_proc=$(proc_counters "$IFACE")
read -r RX_B1 RX_P1 RX_E1 RX_D1 TX_B1 TX_P1 TX_E1 TX_D1 <<< "$after_proc"
ethtool_counters "$IFACE" > "$after_ethtool"

drx_b=$((RX_B1 - RX_B0)); drx_p=$((RX_P1 - RX_P0))
drx_e=$((RX_E1 - RX_E0)); drx_d=$((RX_D1 - RX_D0))
dtx_b=$((TX_B1 - TX_B0)); dtx_p=$((TX_P1 - TX_P0))
dtx_e=$((TX_E1 - TX_E0)); dtx_d=$((TX_D1 - TX_D0))

# ---------- report ----------
echo
echo "============= NIC counters delta over ${ELAPSED}s on $IFACE ============="
echo "/proc/net/dev (kernel-stack visible only — usually low under AF_XDP):"
printf "  RX bytes  : %15d  (%.3f Gbps avg)\n" "$drx_b" \
    "$(awk -v b=$drx_b -v t=$ELAPSED 'BEGIN{print (t>0)? b*8/t/1e9 : 0}')"
printf "  RX packets: %15d  (%.0f pps avg)\n"  "$drx_p" \
    "$(awk -v p=$drx_p -v t=$ELAPSED 'BEGIN{print (t>0)? p/t : 0}')"
printf "  RX errs   : %15d\n" "$drx_e"
printf "  RX drops  : %15d\n" "$drx_d"
printf "  TX bytes  : %15d  (%.3f Gbps avg)\n" "$dtx_b" \
    "$(awk -v b=$dtx_b -v t=$ELAPSED 'BEGIN{print (t>0)? b*8/t/1e9 : 0}')"
printf "  TX packets: %15d  (%.0f pps avg)\n"  "$dtx_p" \
    "$(awk -v p=$dtx_p -v t=$ELAPSED 'BEGIN{print (t>0)? p/t : 0}')"
printf "  TX errs   : %15d\n" "$dtx_e"
printf "  TX drops  : %15d\n" "$dtx_d"

echo
echo "ethtool -S delta (driver-level — sees AF_XDP traffic):"
ethtool_delta "$before_ethtool" "$after_ethtool"
rm -f "$before_ethtool" "$after_ethtool"

# ---------- echo back epwget's own cumulative summary from the log ----------
echo
echo "================= epwget self-reported summary ================="
awk '/=== epwget cumulative totals ===/{flag=1} flag; /^=====/{if(flag>1)exit; flag++}' "$LOG" || true

echo
echo "(full log: $LOG)"
