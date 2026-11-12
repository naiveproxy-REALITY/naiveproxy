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
- Preserve the downstream Chrome Root Store v43 and certificate distrust policy.
- Restore the two Chromium i18n generators required by the updated prefs types,
  using their ICU-independent targets for standalone Cronet.
- Download Chromium 154's separate Android compiler-rt package even when the
  desktop compiler was already cached.

Build and regression-test this source through the parent cronet-go repository.
The Go bindings and native library must come from the same integration revision.
