# Chromium 154 integration

This branch is based on naiveproxy `v154.0.8037.49-5`
(`d04efe1ea4477c2db24a7d0e2f068b3bee931e45`).

`src/components/cronet` and `src/components/prefs` are restored from Chromium
`154.0.8037.49`. The standalone C API, grpc_support, socket callbacks, Browser
ECH/REALITY, and connection-pool fixes are ported from the previous cronet-go
revision `3da1a5f954fc8ed4e9856e63bed1ed518dfdc585`.

Integration changes for this release:

- Use Chromium's native Strict ECH implementation and updated DNS resolver mode.
- Adapt REALITY to BoringSSL's opaque SSL interface while preserving transcript,
  CertificateVerify, Finished, and camouflage-connection verification.
- Allocate `ERR_REALITY_AUTHENTICATION_FAILED` as `-10000`; Chromium now uses
  its previous value, `-189`, for `ERR_CONTROL_MSG_TOO_BIG`.
- Use Chrome Root Store v45 and preserve the certificate distrust policy.
- Populate ClientHello Trust Anchor IDs from the verification roots, including
  the matching subset when an explicit PEM root store is selected.
- Restore the two Chromium i18n generators required by the updated prefs types,
  using their ICU-independent targets for standalone Cronet.
- Keep URLRequest independent of the Android Java PCC audit logger: the
  standalone C API is initialized without a JVM or generated Java bindings.
- Use libc++'s section-boundary override detection on MIPS, where local inline
  assembly aliases can produce unpaired GOT16 relocations and false assertions
  in `operator new(..., std::nothrow)`. Actual overrides remain detectable.
- Guard macOS 26's standardized spawn chdir API by SDK availability, retaining
  the existing `_np` fallback for older SDKs and deployment targets.
- Download Chromium 154's separate Android compiler-rt package even when the
  desktop compiler was already cached.
- Expose per-engine HTTP ALPN selection. Explicit TCP offers preserve order and
  exclude unrequested fallback protocols; `h3` selects QUIC exclusively. Both
  the legacy socket pools and Happy Eyeballs V3 share the policy.
- Report platform DNS as unavailable in standalone Android Cronet. Strict ECH
  must retain the configured built-in DNS/socket callbacks instead of forcing
  a platform attempt through a factory that the standalone engine never installs.

Build and regression-test this source through the parent cronet-go repository.
The Go bindings and native library must come from the same integration revision.

## Root-store snapshot

The classic root-store data (`root_store.textproto`, `root_store.certs`,
`additional.certs`, and `root_store.md`) is synchronized from Chromium commit
`3f600389c807d0fa50d1c0fed9024e53910f9338`, fetched on 2026-11-12. The upstream
store version is 45. Its protobuf metadata and certificate bundles are kept
together so constraints, certificates, and advertised IDs refer to one snapshot.

Chromium 154's default `TLSTrustAnchorIDs` and `NonMtcTrustAnchorIDs` policies
apply. MTC verification remains disabled by default; its separate signer data
uses the Chromium 154-compatible schema.
