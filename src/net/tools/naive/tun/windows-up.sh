#!/bin/sh
# hev-socks5-tunnel post-up-script (Windows / MSYS build).
#
# Loop prevention is handled entirely by naive's `bind-interface: "auto"`, which
# binds naive's outbound sockets to the physical NIC at the socket layer
# (IP_UNICAST_IF). naive->proxy-server traffic therefore never enters the tun,
# so NO per-server host bypass route is required here.
#
# hev invokes:  windows-up.sh <tun_name> <tun_index>
#   $1 tun_name  : Wintun adapter name (e.g. "tun0")
#   $2 tun_index : Windows interface index (NET_IFINDEX) -- used by `route ... IF`
#
# This MSYS shell script drives native `route.exe` / `netsh.exe` and only:
#   * overrides the default route with two /1 routes (0.0.0.0/1 + 128.0.0.0/1)
#     pointing at the tun interface -- these beat the existing 0.0.0.0/0 by
#     being more specific, so we don't touch the physical default,
#   * sets the tun adapter's DNS so queries don't leak out the physical NIC.
#
# Config from env:
#   HEV_TUN_IP   the tun IPv4 address configured in hev (default 198.18.0.1)
#   HEV_DNS      DNS server to set on the tun adapter (default 1.1.1.1)
#
# Run hev as Administrator (Wintun + route changes need it).
# IMPORTANT: start naive BEFORE hev, so naive's "auto" probe runs while the
# real default route is still present.
set -u

TUN_NAME="${1:-tun0}"
TUN_IF="${2:-}"
TUN_IP="${HEV_TUN_IP:-198.18.0.1}"
DNS="${HEV_DNS:-1.1.1.1}"
STATE="${TEMP:-/tmp}/hev-socks5-tunnel.route.state"

echo "TUN_IF=$TUN_IF" > "$STATE"

# default via tun using two /1 routes (more specific than 0.0.0.0/0).
# Route to the tun's own IP (on-link) as the gateway, on interface TUN_IF.
if [ -n "$TUN_IF" ]; then
  route add 0.0.0.0   mask 128.0.0.0 "$TUN_IP" metric 1 IF "$TUN_IF" >/dev/null 2>&1
  route add 128.0.0.0 mask 128.0.0.0 "$TUN_IP" metric 1 IF "$TUN_IF" >/dev/null 2>&1
else
  route add 0.0.0.0   mask 128.0.0.0 "$TUN_IP" metric 1 >/dev/null 2>&1
  route add 128.0.0.0 mask 128.0.0.0 "$TUN_IP" metric 1 >/dev/null 2>&1
fi

# set DNS on the tun adapter so lookups go through the tunnel (anti-leak)
netsh interface ip set dns name="$TUN_NAME" static "$DNS" >/dev/null 2>&1 || true

echo "hev-up: default->$TUN_NAME (IF $TUN_IF); dns=$DNS (naive binds the NIC at the socket layer; no bypass route needed)"
