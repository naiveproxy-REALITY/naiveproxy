// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SSL_REALITY_CONFIG_H_
#define NET_SSL_REALITY_CONFIG_H_

#include <array>
#include <cstdint>

namespace net {

// Immutable credentials for an engine dedicated to one REALITY endpoint.
struct RealityConfig {
  std::array<uint8_t, 32> public_key;
  std::array<uint8_t, 8> short_id;
};

}  // namespace net

#endif  // NET_SSL_REALITY_CONFIG_H_
