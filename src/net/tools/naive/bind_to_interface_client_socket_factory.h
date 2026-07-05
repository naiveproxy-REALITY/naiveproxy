// Copyright 2024 NaiveProxy-REALITY contributors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#ifndef NET_TOOLS_NAIVE_BIND_TO_INTERFACE_CLIENT_SOCKET_FACTORY_H_
#define NET_TOOLS_NAIVE_BIND_TO_INTERFACE_CLIENT_SOCKET_FACTORY_H_

#include <cstdint>
#include <string>

#include "net/socket/client_socket_factory.h"

namespace net {

// A ClientSocketFactory that binds every outbound TCP socket it creates to a
// fixed physical network interface (via SO_BINDTODEVICE / IP_BOUND_IF /
// IP_UNICAST_IF depending on platform), applied through a before-connect
// callback. This lets naive's connections to the upstream proxy / REALITY
// server bypass a TUN device driven by an external tun2socks, without needing
// any bypass routes. Datagram and SSL sockets are delegated to the default
// factory (SSL wraps an already-bound transport socket).
class BindToInterfaceClientSocketFactory : public ClientSocketFactory {
 public:
  explicit BindToInterfaceClientSocketFactory(const std::string& interface_name);

  BindToInterfaceClientSocketFactory(
      const BindToInterfaceClientSocketFactory&) = delete;
  BindToInterfaceClientSocketFactory& operator=(
      const BindToInterfaceClientSocketFactory&) = delete;

  std::unique_ptr<DatagramClientSocket> CreateDatagramClientSocket(
      DatagramSocket::BindType bind_type,
      NetLog* net_log,
      const NetLogSource& source) override;

  std::unique_ptr<TransportClientSocket> CreateTransportClientSocket(
      const AddressList& addresses,
      std::unique_ptr<SocketPerformanceWatcher> socket_performance_watcher,
      NetworkQualityEstimator* network_quality_estimator,
      NetLog* net_log,
      const NetLogSource& source) override;

  std::unique_ptr<SSLClientSocket> CreateSSLClientSocket(
      SSLClientContext* context,
      std::unique_ptr<StreamSocket> stream_socket,
      const HostPortPair& host_and_port,
      const SSLConfig& ssl_config) override;

 private:
  // Resolved interface name actually used for binding (for SO_BINDTODEVICE on
  // Linux). Equals the configured name, or the detected name when "auto".
  std::string resolved_name_;
  // Resolved interface index (0 if resolution failed).
  uint32_t interface_index_ = 0;
};

}  // namespace net

#endif  // NET_TOOLS_NAIVE_BIND_TO_INTERFACE_CLIENT_SOCKET_FACTORY_H_
