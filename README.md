# NaiveProxy-REALITY

A [NaiveProxy](https://github.com/klzgrad/naiveproxy) client hardened with the
[REALITY](https://github.com/XTLS/REALITY) TLS layer. The client reuses
Chromium's network stack (so its TLS ClientHello is byte-for-byte a real
Chrome's), and REALITY makes the handshake indistinguishable from a genuine
visit to a chosen "mirror" website — defeating active TLS-fingerprint probing.

The server side is a companion **Envoy** build (see the
[envoy fork](https://github.com/justinwoo280/envoy)), not Caddy/forwardproxy.

> This is a fork. Upstream NaiveProxy's own README (padding protocol spec,
> Chromium changes) is preserved below from the "Padding protocol" section down.

## What this fork adds

- **REALITY transport** (faithful to `xtls/reality`): Ed25519 ephemeral certs,
  TCP + HTTP/2 only (no H3/QUIC). The client presents Chrome's fingerprint;
  JA4/cipher verified byte-for-byte against real Chrome.
- **`bind-interface`** option: binds outbound sockets to a physical NIC at the
  socket layer (`SO_BINDTODEVICE` / `IP_BOUND_IF` / `IP_UNICAST_IF`), enabling
  loop-free system-wide TUN mode with **no per-server bypass route**. Supports
  `"auto"` detection.
- **System-wide TUN mode** via a separate `hev-socks5-tunnel` process, with
  ready-made hook scripts and a guide: see
  [`src/net/tools/naive/tun/README.md`](src/net/tools/naive/tun/README.md).
- **UDP-over-TCP (UoT)**: standard SOCKS5 `UDP ASSOCIATE` tunneled over the H2
  stream.

## Platforms

Release target: a single `naive` binary.

| Platform | Status |
|----------|--------|
| Linux glibc x64 | built + stress-tested |
| Windows x64 | built (CI); runtime TUN not yet hardware-tested |
| macOS / musl-static | possible (upstream build jobs exist); not wired in this fork's CI |

## Client setup

Run `./naive config.json` to get a SOCKS5 proxy on local port 1080:

```jsonc
{
  "listen": "socks://127.0.0.1:1080",
  "proxy":  "https://user:pass@YOUR_VPS_IP:8443",
  "reality": {
    "server_name": "www.apple.com",      // the mirror host to impersonate
    "public_key":  "<base64 X25519 public key>",
    "short_id":    "<base64 short id>",
    "version":     [1, 0, 0]
  }
  // optional:
  // "no-post-quantum": true          // force plain X25519 (default offers X25519MLKEM768)
  // "bind-interface": "auto"         // socket-layer NIC bind for TUN mode
}
```

The `public_key`/`short_id` pair with the server's `private_key`/`short_id`.
See [`USAGE.txt`](USAGE.txt) for the full parameter list.

## Server setup

The server is Envoy with the REALITY handshaker and the `naive_forward_proxy`
filter, running on a **remote VPS** (never colocated with the client). See the
envoy fork's `NAIVE_SERVER_CONFIG.md` (config invariants, incl. `codec_type:
HTTP2` and `alpn_protocols: ["h2"]`), `NAIVE_BUILD_RUNBOOK.md` (how to build
`envoy-min`), and `DESIGN.md` (architecture, decisions, and root-cause writeups
of every bug found).

## Build from source

CI: [`.github/workflows/build-naive-client.yml`](.github/workflows/build-naive-client.yml)
builds the Linux x64 (debug, for stress testing) and Windows x64 (release)
clients. The upstream full matrix lives in `.github/workflows/build.yml`.

Your REALITY/UoT/bind-interface changes must be committed on the pushed branch —
CI checks out committed code only.

---

# Upstream NaiveProxy documentation

The sections below are inherited from upstream NaiveProxy and describe the
Chromium-net-stack camouflage and the padding protocol, which this fork keeps.

NaïveProxy uses Chromium's network stack to camouflage traffic with strong censorship resistence and low detectablility. Reusing Chrome's stack also ensures best practices in performance and security.

The following traffic attacks are mitigated by using Chromium's network stack:

* Website fingerprinting / traffic classification: mitigated by [traffic multiplexing in HTTP/2](https://arxiv.org/abs/1707.00641) and parroting preambles.
* [TLS parameter fingerprinting](https://arxiv.org/abs/1607.01639): defeated by reusing [Chrome's network stack](https://www.chromium.org/developers/design-documents/network-stack).
* [Active probing](https://ensa.fi/active-probing/): defeated by *application fronting* (upstream) or by REALITY (this fork).
* Length-based traffic analysis: mitigated by padding and fragmentation.

## Padding protocol, an informal specification

The design of this padding protocol opts for low overhead and easier implementation, in the belief that proliferation of expendable, improvised circumvention protocol designs is a better logistical impediment to censorship research than sophisicated designs.

### Proxy payload padding

NaïveProxy proxies bidirectional streams through HTTP/2 (or HTTP/3) CONNECT tunnels. The bidirectional streams operate in a sequence of reads and writes of data. The first `kFirstPaddings` (8) reads and writes in a bidirectional stream after the stream is established are padded in this format:
```c
struct PaddedData {
  uint8_t original_data_size_high;  // original_data_size / 256
  uint8_t original_data_size_low;  // original_data_size % 256
  uint8_t padding_size;
  uint8_t original_data[original_data_size];
  uint8_t zeros[padding_size];
};
```
`padding_size` is a random integer uniformally distributed in [0, `kMaxPaddingSize`] (`kMaxPaddingSize`: 255). `original_data_size` cannot be greater than 65535, or it has to be split into several reads or writes.

`kFirstPaddings` is chosen to be 8 to flatten the packet length distribution spikes formed from common initial handshakes:
- Common client initial sequence: 1. TLS ClientHello; 2. TLS ChangeCipherSpec, Finished; 3. H2 Magic, SETTINGS, WINDOW_UPDATE; 4. H2 HEADERS GET; 5. H2 SETTINGS ACK.
- Common server initial sequence: 1. TLS ServerHello, ChangeCipherSpec, ...; 2. TLS Certificate, ...; 3. H2 SETTINGS; 4. H2 WINDOW_UPDATE; 5. H2 SETTINGS ACK; 6. H2 HEADERS 200 OK.

Further reads and writes after `kFirstPaddings` are unpadded to avoid performance overhead. Also later packet lengths are usually considered less informative.

### H2 RST_STREAM frame padding

In experiments, NaïveProxy tends to send too many RST_STREAM frames per session, an uncommon behavior from regular browsers. To solve this, an END_STREAM DATA frame padded with total length distributed in [48, 72] is prepended to the RST_STREAM frame so it looks like a HEADERS frame. The server often replies to this with a WINDOW_UPDATE because padding is accounted in flow control. Whether this results in a new uncommon behavior is still unclear.

### H2 HEADERS frame padding

The CONNECT request and response frames are too short and too uncommon. To make its length similar to realistic HEADERS frames, a `padding` header is filled with a sequence of symbols that are not Huffman coded and are pseudo-random enough to avoid being indexed. The length of the padding sequence is randomly distributed in [16, 32] (request) or [30, 62] (response).

### Opt-in of padding protocol

NaïveProxy clients should interoperate with any regular HTTP/2 proxies unaware of this padding protocol. NaïveProxy servers (i.e. any proxy server capable of the this padding protocol) should interoperate with any regular HTTP/2 clients (e.g. regular browsers) unaware of this padding protocol.

NaïveProxy servers and clients determines whether the counterpart is capable of this padding protocol by the presence of the `padding` header in the CONNECT request and response respectively. The padding procotol is enabled only if the `padding` header exists.

The first CONNECT request to a server cannot use "Fast Open" to send payload before response, because the server's padding capability has not been determined from the first response and it's unknown whether to send padded or unpadded payload for Fast Open.

## Changes from Chromium upstream

- Minimize source code and build size (0.3% of the original)
- Disable exceptions and RTTI, except on Mac and Android.
- Support OpenWrt builds
- (Android, Linux) Use the builtin verifier instead of the system verifier (drop dependency of NSS on Linux) and read the system trust store from (following Go's behavior in crypto/x509/root_unix.go and crypto/x509/root_linux.go):
  - The file in environment variable SSL_CERT_FILE
  - The first available file of
    -  /etc/ssl/certs/ca-certificates.crt (Debian/Ubuntu/Gentoo etc.)
    -  /etc/pki/tls/certs/ca-bundle.crt (Fedora/RHEL 6)
    -  /etc/ssl/ca-bundle.pem (OpenSUSE)
    -  /etc/pki/tls/cacert.pem (OpenELEC)
    -  /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem (CentOS/RHEL 7)
    -  /etc/ssl/cert.pem (Alpine Linux)
  - Files in the directory of environment variable SSL_CERT_DIR
  - Files in the first available directory of
    -  /etc/ssl/certs (SLES10/SLES11, https://golang.org/issue/12139)
    -  /etc/pki/tls/certs (Fedora/RHEL)
    -  /system/etc/security/cacerts (Android)
- Handle AIA response in PKCS#7 format
- Allow higher socket limits for proxies
- Force tunneling for all sockets
- Support HTTP/2 and HTTP/3 CONNECT tunnel Fast Open using the `fastopen` header
- Pad RST_STREAM frames
