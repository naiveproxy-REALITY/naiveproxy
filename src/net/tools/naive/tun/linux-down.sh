#!/bin/sh
# hev-socks5-tunnel pre-down-script (Linux). Reverts linux-up.sh.
# hev invokes:  linux-down.sh <tun_name> <tun_index>
set -u

STATE="/run/hev-socks5-tunnel.route.state"
GW=""; DEV=""
if [ -f "$STATE" ]; then
  # shellcheck disable=SC1090
  . "$STATE"
fi

# restore the original default route
if [ -n "$GW" ] && [ -n "$DEV" ]; then
  ip route replace default via "$GW" dev "$DEV"
fi

rm -f "$STATE" 2>/dev/null || true
echo "hev-down: reverted (default restored via ${GW:-?} dev ${DEV:-?})"
