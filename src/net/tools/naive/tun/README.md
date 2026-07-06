# System-wide TUN mode for NaiveProxy-REALITY

`naive` is a local SOCKS5 (and HTTP) proxy. To transparently route *all* of a
machine's traffic through it -- including apps that don't honor a proxy setting
-- put a **TUN** device in front of it and let a tun2socks translate IP packets
into SOCKS5.

We do **not** build a TUN into `naive`. Instead we drive the well-maintained,
standalone [`hev-socks5-tunnel`](https://github.com/heiher/hev-socks5-tunnel)
(MIT-licensed, separate process). This keeps the release a single `naive` binary
and keeps the data-plane glue out of the crypto core.

```
        ┌────────── your machine ──────────┐
        │                                   │
  apps ─┼─▶ tun0 ─▶ hev-socks5-tunnel ─▶ naive:1080 ─┐
        │  (default   (tun2socks)      (SOCKS5)      │  REALITY over TCP/H2
        │   route)                                   ▼
        │                                    physical NIC ──────▶ VPS (envoy) ──▶ internet
        └───────────────────────────────────────────┘
```

Everything except the one hop `naive -> VPS` goes through the tun. That single
hop **must not** re-enter the tun, or you get an infinite loop.

## How the loop is prevented (important)

`naive` binds its outbound sockets directly to the physical NIC at the **socket
layer** using `bind-interface`. On Linux this is `SO_BINDTODEVICE`, on macOS
`IP_BOUND_IF`, on Windows `IP_UNICAST_IF`. A socket bound this way ignores the
routing table's default route, so `naive -> VPS` always leaves via the real NIC
and never touches the tun -- **no per-server bypass route is needed**. Both TCP
and UDP outbound sockets are bound (so a `quic://` upstream is covered too);
TLS/REALITY rides on an already-bound TCP socket.

> **Windows caveat.** Unlike Linux `SO_BINDTODEVICE` (a *hard* bind: traffic to
> an unreachable NIC is black-holed, never leaked), Windows `IP_UNICAST_IF` /
> `IPV6_UNICAST_IF` is a routing **hint**. Windows still makes egress decisions
> primarily by connectivity, so under some conditions the stack may send the
> packet out a different (physical) NIC even though the hint points elsewhere.
> In the tun-loop-prevention scenario this is normally harmless (the physical
> NIC is exactly where we want `naive -> VPS` to go), but do not rely on
> `bind-interface` on Windows as a hard confinement/kill-switch guarantee the
> way you can on Linux. If you need a hard guarantee on Windows, add a
> firewall rule pinning the VPS IP to the physical adapter.

Set it to `"auto"` and `naive` will detect the physical interface itself (it
opens a throwaway UDP socket to a public IP, reads the local address the kernel
picked, and matches it to a non-virtual interface; it falls back to enumerating
physical wifi/ethernet adapters).

```jsonc
{
  "listen": "socks://127.0.0.1:1080",
  "proxy":  "https://user:pass@YOUR_VPS_IP:8443",
  "reality": {
    "server_name": "www.apple.com",
    "public_key":  "<base64 x25519 pubkey>",
    "short_id":    "<base64 short id>",
    "version":     [1, 0, 0]
  },
  "bind-interface": "auto"        // or an explicit name like "eth0" / "en0" / "Wi-Fi"
}
```

> **Startup order matters.** Start `naive` **before** `hev` when using
> `"auto"`. The auto-probe must run while the *real* default route is still in
> place; if the tun has already taken over the default route, the probe would
> pick the tun. (An explicit interface name has no such ordering requirement.)

> **Linux capability.** `SO_BINDTODEVICE` needs `CAP_NET_RAW`. Run `naive` as
> root, or grant it: `setcap cap_net_raw+ep ./naive`.

## Getting hev-socks5-tunnel

It is a separate project; build it once:

```sh
git clone --recursive https://github.com/heiher/hev-socks5-tunnel
cd hev-socks5-tunnel
make            # produces bin/hev-socks5-tunnel
```

On Windows it uses [Wintun](https://www.wintun.net/) (drop `wintun.dll` next to
the binary).

## hev configuration

`hev.yml` (Linux example):

```yaml
tunnel:
  name: tun0
  mtu: 8500
  ipv4: 198.18.0.1
  post-up-script: /path/to/naive/tun/linux-up.sh
  pre-down-script: /path/to/naive/tun/linux-down.sh

socks5:
  port: 1080
  address: 127.0.0.1
  udp: 'udp'          # MUST be 'udp' (standard SOCKS5 UDP ASSOCIATE, which naive
                      # implements via UDP-over-TCP). Do NOT use 'tcp'.

misc:
  log-level: info
```

The `post-up-script` / `pre-down-script` hooks are invoked by hev as
`script <tun_name> <tun_index>`. They set the system default route to the tun
after it is created and revert it on shutdown. Because `naive` bypasses at the
socket layer, the hooks do **not** install any per-server bypass route.

### The hook scripts

| OS      | up                | down                | route override                         |
|---------|-------------------|---------------------|----------------------------------------|
| Linux   | `linux-up.sh`     | `linux-down.sh`     | `ip route replace default dev tun0`    |
| macOS   | `macos-up.sh`     | `macos-down.sh`     | `route change default -interface utun` |
| Windows | `windows-up.sh`   | `windows-down.sh`   | two `/1` routes (0/1 + 128/1) via tun  |

Windows env knobs (set before launching hev): `HEV_TUN_IP` (default
`198.18.0.1`), `HEV_DNS` (DNS to pin on the tun adapter, default `1.1.1.1`).

## Running

```sh
# 1) start naive first (auto-probe needs the real default route)
sudo ./naive naive_client.json &

# 2) then start hev as root/Administrator (it needs the tun + route changes)
sudo ./hev-socks5-tunnel hev.yml
```

Shut down by stopping hev first (its pre-down hook restores routing), then naive.

## Verifying

```sh
curl -sS -o /dev/null -w '%{http_code}\n' https://1.1.1.1/     # TCP through the tun
dig +short @1.1.1.1 example.com                                # UDP(DNS) through the tun
ip route get 1.1.1.1     # -> dev tun0     (app traffic enters the tunnel)
ip route get YOUR_VPS_IP # -> dev <NIC>    (proxy hop stays on the physical link)
```

This chain (TCP + UDP) has been validated end-to-end against a remote envoy
server: default route on the tun, no per-server bypass route, `bind-interface:
"auto"`.

## Troubleshooting

- **`SO_BINDTODEVICE ... failed (needs CAP_NET_RAW)`** — run naive as root or
  `setcap cap_net_raw+ep ./naive`.
- **`bind-interface: cannot resolve interface '<name>'`** — the explicit name is
  wrong; use `"auto"` or the exact adapter name (`ip link` / `ifconfig` /
  `netsh interface show interface`).
- **`bind-interface auto: could not detect a physical interface`** — auto-probe
  failed (e.g. no default route at start, or naive started after hev). Start
  naive first, or set an explicit interface name.
- **Everything hangs / loops** — the proxy hop is re-entering the tun. Confirm
  `ip route get YOUR_VPS_IP` shows the physical NIC and that `naive` logged its
  chosen interface (run with `--v=1` to surface the INFO line).
- **DNS leaks on Windows** — make sure `HEV_DNS` is set and the tun adapter's DNS
  was pinned (`netsh interface ip show dns`).
- **UDP doesn't work** — hev's `socks5.udp` must be `'udp'`, not `'tcp'`.
