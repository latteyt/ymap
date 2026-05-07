#!/bin/bash


cd "$(dirname "$0")" || { echo "Failed to changed directory" >&2; exit 1; }

YMAP="../build/ymap"
[[ ! -x "$YMAP" ]] && { echo "Error: $YMAP not found" >&2; exit 1; }

[[ -z "$IF_NAME" ]] && echo "Error: environment variable 'IF_NAME' is not set" >&2 && exit 1
L3_SRC=$(ip -6 addr show dev "$IF_NAME" | grep "inet6" | grep "global" | awk '!seen[$2]++{print $2}' | cut -d'/' -f1)
L2_DST=$(ip -6 neigh show dev "$IF_NAME" | grep "router" | awk '!seen[$3]++{print $3}')
[[ -z "$L3_SRC" ]] && echo "Error: no global IPv6 address on $IF_NAME" >&2 && exit 1
[[ -z "$L2_DST" ]] && echo "Error: no router neighbor found on $IF_NAME" >&2 && exit 1

SCAN_RATE="${SCAN_RATE:-100000}"
SHARD="${SHARD:-1}"
SEED="${SEED:-123}"


# Generate a scan config for the current prefix length.
# Each round scans one prefix size and feeds its output into the next round.
generate_ini_file() {
  cat <<EOF > "scan.ini"
[Interface]
name    = $IF_NAME
l2_dst  = $L2_DST
l3_src  = $L3_SRC

[Runtime]
shard   = $SHARD
rate    = $SCAN_RATE
repeat  = $REPEAT

[Scan]
type    = net
module  = icmp6_echo
$( [[ -v INPUT ]] && echo "input   = $INPUT" )

[Optional]
$( [[ -v SEED ]] && echo "seed    = $SEED" )
limit   = $LIMIT
iid     = rand
EOF
}


# Scan from shorter prefixes to longer prefixes, pruning redundant space after
# each round before generating the next round's input list.

# Keep only prefixes whose responses share the same prefix fingerprint.
# This is the pruning step that decides which prefixes should be explored deeper.
# `filter` checks whether the discovered periphery and the target address
# belong to the same IPv6 prefix. Since IPv6 forwarding is prefix-based,
# this helps decide whether the prefix should be explored further.
#
# icmp6_echo output fields : ip, common_prefix_length, ...

today=$(date +%Y%m%d)

rm -f scan.ini "output$today.txt"



REPEAT=4096 LIMIT=24 generate_ini_file
[[ ! -f "scan.ini" ]] && { echo "Error: scan.ini not found" >&2; exit 1; }
sudo "$YMAP" "scan.ini" | awk -F, '$3<128{print $1","$2}' | tee -a "output$today.txt" | awk -F, '$2>=24 && !seen[(p=substr($1,1,7))]++{print p"00::/24"}' > prefix24.txt

REPEAT=1024 LIMIT=32 INPUT="prefix24.txt" generate_ini_file
[[ ! -f "scan.ini" ]] && { echo "Error: scan.ini not found" >&2; exit 1; }
sudo "$YMAP" "scan.ini" | awk -F, '$3<128{print $1","$2}' | tee -a "output$today.txt" | awk -F, '$2>=32 && !seen[(p=substr($1,1,9))]++{print p"::/32"}' > prefix32.txt

REPEAT=256 LIMIT=48 INPUT="prefix32.txt" generate_ini_file
[[ ! -f "scan.ini" ]] && { echo "Error: scan.ini not found" >&2; exit 1; }
sudo "$YMAP" "scan.ini" | awk -F, '$3<128{print $1","$2}' | tee -a "output$today.txt" | awk -F, '$2>=48 && !seen[(p=substr($1,1,14))]++{print p"::/48"}' > prefix48.txt
