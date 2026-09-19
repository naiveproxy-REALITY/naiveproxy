// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/ssl/ssl_config_service_defaults.h"

namespace net {

SSLConfigServiceDefaults::SSLConfigServiceDefaults() = default;
SSLConfigServiceDefaults::SSLConfigServiceDefaults(EchMode ech_mode)
    : ech_mode_(ech_mode) {}
SSLConfigServiceDefaults::~SSLConfigServiceDefaults() = default;

SSLConfigServiceDefaults::SSLConfigServiceDefaults(
    EchMode ech_mode, std::optional<RealityConfig> reality)
    : ech_mode_(ech_mode), reality_(reality) {}

const RealityConfig* SSLConfigServiceDefaults::GetRealityConfig() const {
  return reality_ ? &*reality_ : nullptr;
}

SSLContextConfig SSLConfigServiceDefaults::GetSSLContextConfig() {
  return default_config_;
}

bool SSLConfigServiceDefaults::CanShareConnectionWithClientCerts(
    std::string_view hostname) const {
  return false;
}

EchMode SSLConfigServiceDefaults::GetEchMode(std::string_view hostname) const {
  return ech_mode_;
}

}  // namespace net
