#!/bin/sh
# hev-socks5-tunnel pre-down-script (Windows / MSYS build). Reverts windows-up.sh.
# hev invokes:  windows-down.sh <tun_name> <tun_index>
set -u

TUN_IP="${HEV_TUN_IP:-198.18.0.1}"
STATE="${TEMP:-/tmp}/hev-socks5-tunnel.route.state"

# remove the two /1 default-override routes
route delete 0.0.0.0   mask 128.0.0.0 "$TUN_IP" >/dev/null 2>&1 || true
route delete 128.0.0.0 mask 128.0.0.0 "$TUN_IP" >/dev/null 2>&1 || true

# (physical default route was never deleted, so nothing to restore for it)
rm -f "$STATE" 2>/dev/null || true
echo "hev-down: reverted (/1 default-override removed)"
