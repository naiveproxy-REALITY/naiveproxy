// Copyright 2024 NaiveProxy-REALITY contributors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include "net/tools/naive/bind_to_interface_client_socket_factory.h"

#include "base/functional/bind.h"
#include "base/logging.h"
#include "build/build_config.h"
#include "net/base/net_errors.h"
#include "net/socket/tcp_client_socket.h"

#if BUILDFLAG(IS_WIN)
#include <winsock2.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>  // if_nametoindex
#else
#include <net/if.h>       // if_nametoindex, IFNAMSIZ
#include <netinet/in.h>   // IPPROTO_IP, IP(V6)_BOUND_IF
#include <sys/socket.h>   // setsockopt, SO_BINDTODEVICE
#endif

namespace net {

namespace {

uint32_t ResolveInterfaceIndex(const std::string& name) {
  if (name.empty())
    return 0;
  uint32_t idx = if_nametoindex(name.c_str());
  if (idx == 0) {
    LOG(ERROR) << "bind-interface: cannot resolve interface '" << name << "'";
  }
  return idx;
}

// Runs as the socket's BeforeConnectCallback: the fd exists and is not yet
// connected. Binds it to the chosen interface. Returns a net error.
int BindFdToInterface(uint32_t if_index,
                      const std::string& if_name,
                      SocketDescriptor fd) {
  if (if_index == 0 || fd == kInvalidSocket)
    return OK;  // nothing to do / disabled

#if BUILDFLAG(IS_WIN)
  // IPv4: IP_UNICAST_IF takes the index in NETWORK byte order.
  DWORD idx_be = htonl(if_index);
  int rv4 = setsockopt(fd, IPPROTO_IP, IP_UNICAST_IF,
                       reinterpret_cast<const char*>(&idx_be), sizeof(idx_be));
  // IPv6: IPV6_UNICAST_IF takes the index in HOST byte order.
  DWORD idx_h = if_index;
  int rv6 = setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_IF,
                       reinterpret_cast<const char*>(&idx_h), sizeof(idx_h));
  if (rv4 != 0 && rv6 != 0) {
    PLOG(ERROR) << "bind-interface: IP(V6)_UNICAST_IF failed";
    return ERR_FAILED;
  }
#elif BUILDFLAG(IS_APPLE) || BUILDFLAG(IS_BSD)
  int idx = static_cast<int>(if_index);
  int rv4 = setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &idx, sizeof(idx));
  int rv6 = setsockopt(fd, IPPROTO_IPV6, IPV6_BOUND_IF, &idx, sizeof(idx));
  if (rv4 != 0 && rv6 != 0) {
    PLOG(ERROR) << "bind-interface: IP(V6)_BOUND_IF failed";
    return ERR_FAILED;
  }
#else  // Linux / Android
  // SO_BINDTODEVICE binds by name and covers both v4 and v6. Needs CAP_NET_RAW.
  if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, if_name.c_str(),
                 static_cast<socklen_t>(if_name.size())) != 0) {
    PLOG(ERROR) << "bind-interface: SO_BINDTODEVICE(" << if_name
                << ") failed (needs CAP_NET_RAW)";
    return ERR_FAILED;
  }
#endif
  return OK;
}

}  // namespace

BindToInterfaceClientSocketFactory::BindToInterfaceClientSocketFactory(
    const std::string& interface_name)
    : interface_name_(interface_name),
      interface_index_(ResolveInterfaceIndex(interface_name)) {
  LOG(INFO) << "bind-interface: outbound sockets bound to '" << interface_name_
            << "' (index " << interface_index_ << ")";
}

std::unique_ptr<DatagramClientSocket>
BindToInterfaceClientSocketFactory::CreateDatagramClientSocket(
    DatagramSocket::BindType bind_type,
    NetLog* net_log,
    const NetLogSource& source) {
  return ClientSocketFactory::GetDefaultFactory()->CreateDatagramClientSocket(
      bind_type, net_log, source);
}

std::unique_ptr<TransportClientSocket>
BindToInterfaceClientSocketFactory::CreateTransportClientSocket(
    const AddressList& addresses,
    std::unique_ptr<SocketPerformanceWatcher> socket_performance_watcher,
    NetworkQualityEstimator* network_quality_estimator,
    NetLog* net_log,
    const NetLogSource& source) {
  auto socket = std::make_unique<TCPClientSocket>(
      addresses, std::move(socket_performance_watcher),
      network_quality_estimator, net_log, source);
  // Bind at connect time: the fd is open but not yet connected when the
  // before-connect callback runs.
  TCPClientSocket* raw = socket.get();
  uint32_t idx = interface_index_;
  std::string name = interface_name_;
  raw->SetBeforeConnectCallback(base::BindRepeating(
      [](uint32_t if_index, const std::string& if_name,
         TCPClientSocket* sock) -> int {
        return BindFdToInterface(if_index, if_name,
                                 sock->SocketDescriptorForTesting());
      },
      idx, std::move(name), base::Unretained(raw)));
  return socket;
}

std::unique_ptr<SSLClientSocket>
BindToInterfaceClientSocketFactory::CreateSSLClientSocket(
    SSLClientContext* context,
    std::unique_ptr<StreamSocket> stream_socket,
    const HostPortPair& host_and_port,
    const SSLConfig& ssl_config) {
  return ClientSocketFactory::GetDefaultFactory()->CreateSSLClientSocket(
      context, std::move(stream_socket), host_and_port, ssl_config);
}

}  // namespace net
