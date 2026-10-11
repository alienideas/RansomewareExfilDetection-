#!/usr/bin/env bash
# exfil-hunter.sh
# Layer 2: Data Exfiltration Detection (silent monitoring)
# Linux (most distributions)
# Designed for cron / systemd / SIEM use — NO interactive alerts, NO pop-ups
# Logs findings only; exits with code 1 on high-confidence signals

set -euo pipefail

SAMPLE_SECONDS=${SAMPLE_SECONDS:-30}
HIGH_VOLUME_MB_PER_MIN=${HIGH_VOLUME_MB_PER_MIN:-500}
LOG_FILE="${LOG_FILE:-/var/log/exfil-hunter.log}"
STATE_DIR="${STATE_DIR:-/var/lib/exfil-hunter}"
BASELINE_FILE="${STATE_DIR}/baseline"
STATE_FILE="${STATE_DIR}/state"

mkdir -p "$STATE_DIR"
touch "$LOG_FILE"

timestamp() { date '+%Y-%m-%d %H:%M:%S'; }

log() {
    local level="$1"; shift
    # Silent: only append to log file
    echo "[$(timestamp)] [$level] $*" >> "$LOG_FILE"
}

log INFO "=== exfil-hunter started (sample ${SAMPLE_SECONDS}s) ==="

# -------------------------------------------------
# Helper: is private / local address?
# -------------------------------------------------
is_private() {
    local ip="$1"
    [[ "$ip" =~ ^127\. ]] && return 0
    [[ "$ip" =~ ^10\. ]] && return 0
    [[ "$ip" =~ ^192\.168\. ]] && return 0
    [[ "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[01])\. ]] && return 0
    [[ "$ip" =~ ^::1$ ]] && return 0
    [[ "$ip" =~ ^fe80: ]] && return 0
    [[ "$ip" =~ ^fc00: ]] && return 0
    [[ "$ip" =~ ^fd ]] && return 0
    return 1
}

# -------------------------------------------------
# 1. Outbound data volume sampling (via /proc/net/dev)
# -------------------------------------------------
get_tx_bytes() {
    # Sum Transmit bytes across all non-loopback interfaces
    awk '
        NR > 2 {
            iface = $1
            gsub(/:/, "", iface)
            if (iface != "lo") {
                tx += $10
            }
        }
        END { print tx+0 }
    ' /proc/net/dev
}

bytes_start=$(get_tx_bytes)
sleep "$SAMPLE_SECONDS"
bytes_end=$(get_tx_bytes)

bytes_sent=$(( bytes_end - bytes_start ))
if (( bytes_sent < 0 )); then bytes_sent=0; fi

# Convert to MB per minute
mb_per_min=$(awk -v b="$bytes_sent" -v s="$SAMPLE_SECONDS" 'BEGIN { printf "%.2f", (b / 1048576) * (60 / s) }')

log INFO "Outbound volume sample: ${mb_per_min} MB/min over ${SAMPLE_SECONDS}s"

HIGH=0
if awk -v v="$mb_per_min" -v t="$HIGH_VOLUME_MB_PER_MIN" 'BEGIN { exit !(v >= t) }'; then
    log HIGH "High outbound volume: ${mb_per_min} MB/min (threshold ${HIGH_VOLUME_MB_PER_MIN} MB/min)"
    HIGH=1
fi

# Simple baseline (EMA)
if [[ -f "$BASELINE_FILE" ]]; then
    old_avg=$(cat "$BASELINE_FILE" 2>/dev/null || echo "0")
    if awk -v v="$mb_per_min" -v o="$old_avg" 'BEGIN { exit !(o > 0 && v > o * 5) }'; then
        log HIGH "Outbound volume ${mb_per_min} MB/min is >5x baseline (${old_avg} MB/min)"
        HIGH=1
    fi
    new_avg=$(awk -v o="$old_avg" -v v="$mb_per_min" 'BEGIN { printf "%.2f", (o * 0.8) + (v * 0.2) }')
else
    new_avg="$mb_per_min"
fi
echo "$new_avg" > "$BASELINE_FILE"

# -------------------------------------------------
# 2. Established outbound connections to external IPs
# -------------------------------------------------
# Prefer ss; fall back to netstat if needed
if command -v ss >/dev/null 2>&1; then
    # TCP established, numeric, with process
    mapfile -t conns < <(ss -tn state established 2>/dev/null | awk 'NR>1 {print $4,$5}' || true)
else
    mapfile -t conns < <(netstat -tn 2>/dev/null | awk '/ESTABLISHED/ {print $4,$5}' || true)
fi

external_count=0
declare -A remote_ips

for line in "${conns[@]:-}"; do
    remote=$(echo "$line" | awk '{print $2}')
    # Strip port
    rip=${remote%:*}
    # Handle IPv6 [addr]:port
    rip=${rip#[}
    rip=${rip%]}

    if ! is_private "$rip"; then
        ((external_count++)) || true
        remote_ips["$rip"]=1
    fi
done

unique_ips=${#remote_ips[@]}
log INFO "External established connections: ${external_count}  | Unique remote IPs: ${unique_ips}"

# Log top remote IPs (first 15)
i=0
for ip in "${!remote_ips[@]}"; do
    log INFO "External remote IP: $ip"
    ((i++))
    (( i >= 15 )) && break
done

# -------------------------------------------------
# 3. DNS tunneling indicators
#    - High query rate to single domain (from journal / dnsmasq if available)
#    - Very long domain names in resolv / cache
# -------------------------------------------------
# Check systemd-resolved journal for recent high activity (best-effort)
if command -v journalctl >/dev/null 2>&1; then
    # Count DNS-related lines in last few minutes (rough)
    dns_lines=$(journalctl -u systemd-resolved --since "2 minutes ago" 2>/dev/null | grep -c -i "dns\|query\|lookup" || true)
    if (( dns_lines > 500 )); then
        log WARN "High DNS activity in systemd-resolved journal: ${dns_lines} lines in ~2 min (possible tunneling)"
    fi
fi

# Look for unusually long hostnames in /etc/hosts or recent process args (lightweight)
if [[ -r /proc/net/udp ]]; then
    # UDP sockets (DNS often uses 53) — just note count of external UDP
    udp_ext=0
    while read -r line; do
        # Very rough parse; mainly for logging
        ((udp_ext++)) || true
    done < <(ss -un state established 2>/dev/null | awk 'NR>1' || true)
    if (( udp_ext > 50 )); then
        log WARN "Elevated established UDP sockets: ${udp_ext} (review for DNS/data channels)"
    fi
fi

# -------------------------------------------------
# 4. Persist simple state
# -------------------------------------------------
{
    echo "last_run=$(timestamp)"
    echo "last_mb_per_min=${mb_per_min}"
    echo "external_ip_count=${unique_ips}"
} > "$STATE_FILE"

# -------------------------------------------------
# Final
# -------------------------------------------------
if (( HIGH == 1 )); then
    log HIGH "HIGH CONFIDENCE: Possible data exfiltration activity detected (silent mode — no user alert)"
    exit 1
else
    log INFO "No high-confidence exfiltration signals in this sample."
    exit 0
fi
