#!/bin/sh
# hev-socks5-tunnel pre-down-script (macOS / FreeBSD). Reverts macos-up.sh.
# hev invokes:  macos-down.sh <tun_name> <tun_index>
set -u

STATE="/tmp/hev-socks5-tunnel.route.state"
GW=""
if [ -f "$STATE" ]; then
  # shellcheck disable=SC1090
  . "$STATE"
fi

# restore original default gateway
if [ -n "$GW" ]; then
  route -n change default "$GW" 2>/dev/null || route -n add default "$GW" 2>/dev/null || true
fi

rm -f "$STATE" 2>/dev/null || true
echo "hev-down: reverted (default restored via ${GW:-?})"
