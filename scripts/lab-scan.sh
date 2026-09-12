#!/usr/bin/env bash
# Baseline scans for RK_BA19C. Run inside `nix-shell` from this repo.
# Usage: ./lab-scan.sh <bulb_ip> <iface>
set -euo pipefail
BULB_IP="${1:?usage: lab-scan.sh <bulb_ip> <iface>}"
IFACE="${2:?usage: lab-scan.sh <bulb_ip> <iface>}"
OUT="captures"
mkdir -p "$OUT"

echo "=== TCP full port scan ==="
sudo nmap -sS -sV -p- "$BULB_IP" | tee "$OUT/nmap-tcp-$BULB_IP.txt"

echo "=== UDP top 200 ==="
sudo nmap -sU --top-ports 200 "$BULB_IP" | tee "$OUT/nmap-udp-$BULB_IP.txt"

echo "=== ARP and OUI check ==="
ip neigh show | grep -i "$BULB_IP" || true

echo "pcap hint: sudo tcpdump -ni $IFACE host $BULB_IP -w $OUT/baseline-$BULB_IP.pcap"
echo "then repeat per action: power-on, power-off, brightness, color, cct, reset, pairing"
