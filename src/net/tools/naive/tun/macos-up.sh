#!/bin/sh
# hev-socks5-tunnel post-up-script (macOS / FreeBSD).
#
# Loop prevention is handled entirely by naive's `bind-interface: "auto"`, which
# binds naive's outbound sockets to the physical NIC at the socket layer
# (IP_BOUND_IF). naive->proxy-server traffic therefore never enters the tun, so
# NO per-server host bypass route is required here.
#
# hev invokes:  macos-up.sh <tun_name> <tun_index>      (tun_name is like "utun5")
#
# This script only:
#   * saves the original default gateway (so macos-down.sh can restore it),
#   * points the default route at the tun interface (all app traffic).
#
# Requires: root. macOS uses `route`.
# IMPORTANT: start naive BEFORE hev, so naive's "auto" probe runs while the
# real default route is still present.
set -eu

TUN_NAME="${1:-utun0}"
STATE="/tmp/hev-socks5-tunnel.route.state"

GW="$(route -n get default 2>/dev/null | awk '/gateway:/{print $2; exit}')"
if [ -z "$GW" ]; then
  echo "hev-up: cannot determine default gateway; aborting" >&2
  exit 1
fi
: > "$STATE"
echo "GW=$GW" >> "$STATE"

# default route -> tun interface (v4 and v6); naive bypasses at the socket layer
route -n change default -interface "$TUN_NAME" 2>/dev/null || \
  route -n add default -interface "$TUN_NAME"
route -n change -inet6 default -interface "$TUN_NAME" 2>/dev/null || true

echo "hev-up: default->$TUN_NAME (naive binds the NIC at the socket layer; no bypass route needed)"
