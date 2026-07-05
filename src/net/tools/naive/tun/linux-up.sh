#!/bin/sh
# hev-socks5-tunnel post-up-script (Linux).
#
# Loop prevention is handled entirely by naive's `bind-interface: "auto"`, which
# binds naive's outbound sockets to the physical NIC at the socket layer
# (SO_BINDTODEVICE). naive->proxy-server traffic therefore never enters the tun,
# so NO per-server /32 bypass route is required here.
#
# hev invokes:  linux-up.sh <tun_name> <tun_index>
#
# This script only:
#   * saves the current default route (so linux-down.sh can restore it),
#   * replaces the default route to go through the tun (all app traffic),
#   * relaxes reverse-path filtering (asymmetric routing across tun/eth).
#
# Requires: iproute2, root (hev already needs root/NET_ADMIN).
# IMPORTANT: start naive BEFORE hev, so naive's "auto" probe runs while the
# real default route is still present (before the tun takes it over).
set -eu

TUN_NAME="${1:-tun0}"
STATE="/run/hev-socks5-tunnel.route.state"

GW="$(ip route show default | awk '/default/{print $3; exit}')"
DEV="$(ip route show default | awk '/default/{print $5; exit}')"
if [ -z "$GW" ] || [ -z "$DEV" ]; then
  echo "hev-up: cannot determine default gateway; aborting" >&2
  exit 1
fi
: > "$STATE"
echo "GW=$GW"   >> "$STATE"
echo "DEV=$DEV" >> "$STATE"

# send the default route through the tun (naive bypasses at the socket layer)
ip route replace default dev "$TUN_NAME"

# relax reverse-path filtering (asymmetric routing across tun/eth)
sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1 || true
sysctl -w "net.ipv4.conf.${TUN_NAME}.rp_filter=0" >/dev/null 2>&1 || true

echo "hev-up: default->$TUN_NAME (naive binds the NIC at the socket layer; no bypass route needed)"
