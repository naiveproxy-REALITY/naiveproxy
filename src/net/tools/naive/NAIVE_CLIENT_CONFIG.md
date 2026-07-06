# NaiveProxy-REALITY client — configuration guide

How to configure the `naive` client to connect to a NaiveProxy-REALITY Envoy
server. For the **server** side see the Envoy repo's `NAIVE_SERVER_CONFIG.md`;
for system-wide (TUN) mode see `tun/README.md`.

The client runs locally (your machine / router). The server must be on a
**remote VPS**.

---

## Minimal config

`naive` reads a single JSON file. Minimal working client:

```jsonc
{
  "listen": "socks://127.0.0.1:1080",
  "proxy":  "https://USER:PASS@YOUR_VPS_IP:8443",
  "reality": {
    "server_name": "www.apple.com",
    "public_key":  "<base64 X25519 public key from the server>",
    "short_id":    "<base64 short id, matches the server>",
    "version":     [1, 0, 0]
  }
}
```

Run it:

```sh
./naive client.json
```

Then point your app at the local SOCKS proxy `socks5h://127.0.0.1:1080`
(use `socks5h` so DNS is resolved through the proxy, not locally).

```sh
curl -x socks5h://127.0.0.1:1080 https://www.google.com/
```

---

## The four things that must match the server

| Client field | Must equal server's |
|--------------|---------------------|
| `proxy` user:pass | `naive_forward_proxy` `username` / `password` |
| `proxy` host:port | the server's listen address (e.g. `:8443`) |
| `reality.public_key` | the **public** half of the server's `private_key` (see server guide Step 0) |
| `reality.short_id` | the server's `short_id` (byte-for-byte) |
| `reality.server_name` | the server's `mirror_target` host (e.g. `www.apple.com`) |

If any of these mismatch, the REALITY auth fails and the server treats you as a
prober — you get transparently proxied to the real site (you'll see the real
site's page, not your tunnel). That is the anti-probing fallback working as
intended; it just means your keys are wrong.

---

## Fields reference

### Core

| Field | Meaning |
|-------|---------|
| `listen` | Local listener. `socks://HOST:PORT` (SOCKS5) or `http://HOST:PORT` (HTTP proxy). Bind to `127.0.0.1` unless you intend to expose it. |
| `proxy` | Upstream server URL: `https://USER:PASS@VPS_IP:PORT`. Scheme `https` = REALITY-over-TCP/H2 (the normal case). |
| `reality` | REALITY parameters (below). Presence enables REALITY. |

### `reality` object

| Field | Meaning |
|-------|---------|
| `server_name` | The SNI to present = the mirror/dest host the server borrows (e.g. `www.apple.com`). Must match the server's `mirror_target` host. |
| `public_key` | Base64 of the server's X25519 **public** key (32 bytes). |
| `short_id` | Base64 (1..8 bytes), matches the server. |
| `version` | `[1, 0, 0]`. |

### Optional / tuning

| Field | Meaning |
|-------|---------|
| `no-post-quantum` | `true` to force plain X25519 (skip X25519MLKEM768). Only if your dest/server can't do the PQC hybrid. Default keeps the hybrid, matching modern Chrome. |
| `bind-interface` | Bind outbound sockets to a NIC at the socket layer. `"auto"` = detect the physical NIC (for TUN mode loop-prevention), or an explicit name like `"eth0"` / `"Wi-Fi"`. Empty/absent = normal routing. See `tun/README.md`. |
| `log` | Log destination/level. |
| `ssl-key-log-file` | Path to write TLS keys (debugging only — never in production). |
| `host-resolver-rules` | Override DNS resolution (e.g. pin the VPS hostname to an IP). |
| `extra-headers` | Extra headers on the CONNECT/tunnel request. |
| `idle-timeout`, `tunnel-timeout` | Connection timeouts. |
| `insecure-concurrency` | Number of worker threads (raise for more throughput; the PQC handshake is CPU-bound). |

---

## Verifying it works

1. **Tunnel test** — a request through the SOCKS proxy should reach the internet:
   ```sh
   curl -x socks5h://127.0.0.1:1080 -o /dev/null -w "%{http_code}\n" https://1.1.1.1/
   ```
   A normal HTTP status (200/301/…) means the REALITY tunnel is up.

2. **If you instead get the mirror site's homepage** when requesting some other
   URL, your keys don't match the server (auth failed → server fell back to
   proxying you to the real dest). Re-check `public_key` / `short_id` / user:pass.

---

## System-wide (TUN) mode — full setup

To route **all** traffic (not just apps configured for SOCKS) through naive, pair
it with [`hev-socks5-tunnel`](https://github.com/heiher/hev-socks5-tunnel). naive
runs as a local SOCKS proxy; hev creates a TUN device, points the system default
route at it, and forwards everything into naive's SOCKS port. Loop-prevention
(naive→VPS must not re-enter the TUN) is handled entirely by
`bind-interface: "auto"` at the socket layer — **no bypass routes needed**.

This walkthrough is for Linux; macOS/Windows differ only in the hook script (see
`tun/README.md`).

### 1. Build hev-socks5-tunnel (once)

```sh
git clone --recursive https://github.com/heiher/hev-socks5-tunnel
cd hev-socks5-tunnel && make          # -> bin/hev-socks5-tunnel
```

### 2. naive client config — add `bind-interface: "auto"`

`client.json` (same as the minimal config, plus one line):

```jsonc
{
  "listen": "socks://127.0.0.1:1080",
  "proxy":  "https://USER:PASS@YOUR_VPS_IP:8443",
  "reality": {
    "server_name": "www.apple.com",
    "public_key":  "<base64 X25519 public key>",
    "short_id":    "<base64 short id>",
    "version":     [1, 0, 0]
  },
  "bind-interface": "auto"            // detect the physical NIC; bind outbound
                                      // sockets to it so naive->VPS skips the TUN
}
```

### 3. hev config — forward the TUN into naive's SOCKS port

`hev.yml`:

```yaml
tunnel:
  name: tun0
  mtu: 8500
  ipv4: 198.18.0.1
  post-up-script:  /path/to/naive/tun/linux-up.sh   # sets default route -> tun0
  pre-down-script: /path/to/naive/tun/linux-down.sh # restores it on shutdown
socks5:
  port: 1080
  address: 127.0.0.1
  udp: 'udp'          # MUST be 'udp' (SOCKS5 UDP ASSOCIATE; naive does UDP-over-TCP)
misc:
  log-level: info
```

The `linux-up.sh` / `linux-down.sh` hook scripts ship in `tun/`. They only swap
the default route to/from the TUN — they install **no** per-server bypass route,
because naive already bypasses at the socket layer.

### 4. Start in the right order (critical)

```sh
# (a) naive FIRST — its "auto" probe must see the real default route before
#     the TUN takes it over.
sudo ./naive client.json &

# (b) then hev (needs root / NET_ADMIN + /dev/net/tun)
sudo ./hev-socks5-tunnel hev.yml &
```

> **Why order matters.** With `bind-interface: "auto"`, naive probes for the
> physical NIC by opening a throwaway socket and seeing which interface the
> kernel picks. If the TUN has already grabbed the default route, the probe would
> pick the TUN → loop. Starting naive first avoids this. (An explicit interface
> name like `"eth0"` has no ordering requirement.)

> **Linux capability.** `SO_BINDTODEVICE` needs `CAP_NET_RAW`. Run naive as root
> or grant it: `sudo setcap cap_net_raw+ep ./naive`.

### 5. Verify

```sh
# All traffic now goes through the tunnel WITHOUT setting any proxy:
curl -o /dev/null -w "%{http_code}\n" https://1.1.1.1/      # TCP via TUN
dig @1.1.1.1 example.com +short                             # UDP(DNS) via TUN
ip route show default                                       # should show: default dev tun0
```

To confirm loop-prevention, the route to your VPS should stay on the physical
NIC, not the TUN:

```sh
ip route get YOUR_VPS_IP        # dev should be eth0 (or your NIC), not tun0
```

### Teardown

Stop hev first (its `pre-down-script` restores the default route), then naive.

> **Windows caveat.** On Windows, `bind-interface` uses `IP_UNICAST_IF`, which is
> a routing *hint*, not a hard bind like Linux `SO_BINDTODEVICE`. Under some
> conditions the stack may still egress via another NIC. Do not rely on it as a
> hard kill-switch on Windows; add a firewall rule pinning the VPS IP to the
> physical adapter if you need a hard guarantee. See `tun/README.md`.

For macOS/Windows hook scripts and full details, see `tun/README.md`.

---

## Notes

- Use `socks5h://` (not `socks5://`) in clients so DNS goes through the proxy;
  otherwise you leak DNS locally.
- The client is the performance bottleneck: the post-quantum (X25519MLKEM768)
  handshake pins a CPU core. Raise `insecure-concurrency` if you need more
  parallel throughput.
- The client's TLS fingerprint (ClientHello) is aligned with real Chrome
  (GREASE, ALPN `h2,http/1.1`, X25519MLKEM768, GREASE ECH). Do not add options
  that would skew it (e.g. forcing plain X25519 changes the key_share and makes
  you look slightly different from current Chrome).
```
