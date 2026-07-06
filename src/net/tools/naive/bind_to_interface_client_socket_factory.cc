// Copyright 2024 NaiveProxy-REALITY contributors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include "net/tools/naive/bind_to_interface_client_socket_factory.h"

#include "base/functional/bind.h"
#include "base/logging.h"
#include "base/strings/string_util.h"
#include "build/build_config.h"
#include "net/base/address_family.h"
#include "net/base/ip_address.h"
#include "net/base/ip_endpoint.h"
#include "net/base/net_errors.h"
#include "net/base/network_interfaces.h"
#include "net/base/sockaddr_storage.h"
#include "net/log/net_log_source.h"
#include "net/socket/datagram_socket.h"
#include "net/socket/socket_descriptor.h"
#include "net/socket/tcp_client_socket.h"
#include "net/socket/udp_client_socket.h"

#if BUILDFLAG(IS_WIN)
#include <winsock2.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>  // if_nametoindex
#else
#include <net/if.h>       // if_nametoindex, IFNAMSIZ
#include <netinet/in.h>   // IPPROTO_IP, IP(V6)_BOUND_IF
#include <sys/socket.h>   // setsockopt, SO_BINDTODEVICE, sockaddr_storage
#include <unistd.h>       // close
#endif

namespace net {

namespace {

// Is this interface name a virtual/tunnel adapter we must never bind to?
bool IsVirtualInterfaceName(const std::string& name) {
  static const char* const kVirtualPrefixes[] = {
      "tun", "utun", "tap", "wg", "wintun", "vmnet", "vnic", "vEthernet",
      "ppp", "ipsec", "gpd", "zt",  // wireguard-windows/zerotier/etc.
  };
  std::string lower = base::ToLowerASCII(name);
  for (const char* p : kVirtualPrefixes) {
    if (lower.rfind(p, 0) == 0)  // startswith
      return true;
  }
  return false;
}

// Primary auto-detect: connect a UDP socket to a public IP and read the local
// address the kernel picked, then match it to an interface. This must run
// BEFORE any TUN takes over the default route (i.e. start naive before the
// tun2socks process), otherwise the kernel would pick the TUN.
uint32_t DetectByProbe(const IPEndPoint& target, std::string* out_name) {
  UDPClientSocket sock(DatagramSocket::DEFAULT_BIND, /*net_log=*/nullptr,
                       NetLogSource());
  if (sock.Connect(target) != OK)
    return 0;
  IPEndPoint local;
  if (sock.GetLocalAddress(&local) != OK)
    return 0;

  NetworkInterfaceList interfaces;
  if (!GetNetworkList(&interfaces, INCLUDE_HOST_SCOPE_VIRTUAL_INTERFACES))
    return 0;
  for (const auto& iface : interfaces) {
    if (iface.address == local.address() &&
        !IsVirtualInterfaceName(iface.name)) {
      LOG(INFO) << "bind-interface auto: probe picked '" << iface.name
                << "' (index " << iface.interface_index << ")";
      *out_name = iface.name;
      return iface.interface_index;
    }
  }
  return 0;
}

// Fallback: enumerate interfaces and pick a physical one (wifi/ethernet, has a
// MAC, not a virtual/tun name).
uint32_t DetectByEnumeration(std::string* out_name) {
  NetworkInterfaceList interfaces;
  if (!GetNetworkList(&interfaces, INCLUDE_HOST_SCOPE_VIRTUAL_INTERFACES))
    return 0;
  for (const auto& iface : interfaces) {
    if (IsVirtualInterfaceName(iface.name))
      continue;
    if (iface.type != NetworkChangeNotifier::CONNECTION_WIFI &&
        iface.type != NetworkChangeNotifier::CONNECTION_ETHERNET)
      continue;
    if (!iface.mac_address.has_value())
      continue;  // TUN/TAP usually have no MAC
    LOG(INFO) << "bind-interface auto: enumeration picked '" << iface.name
              << "' (index " << iface.interface_index << ")";
    *out_name = iface.name;
    return iface.interface_index;
  }
  return 0;
}

uint32_t DetectOutboundInterface(std::string* out_name) {
  // Try IPv4 then IPv6 public anycast DNS as probe targets.
  uint32_t idx = DetectByProbe(IPEndPoint(IPAddress(8, 8, 8, 8), 53), out_name);
  if (idx == 0) {
    IPAddress v6;
    if (v6.AssignFromIPLiteral("2001:4860:4860::8888"))
      idx = DetectByProbe(IPEndPoint(v6, 53), out_name);
  }
  if (idx == 0)
    idx = DetectByEnumeration(out_name);
  if (idx == 0)
    LOG(ERROR) << "bind-interface auto: could not detect a physical interface";
  return idx;
}

// Resolves the configured value to (index, name). "auto" triggers detection.
uint32_t ResolveInterface(const std::string& name, std::string* out_name) {
  if (name.empty())
    return 0;
  if (name == "auto")
    return DetectOutboundInterface(out_name);
  uint32_t idx = if_nametoindex(name.c_str());
  if (idx == 0) {
    LOG(ERROR) << "bind-interface: cannot resolve interface '" << name << "'";
    return 0;
  }
  *out_name = name;
  return idx;
}

// Returns the address family (AF_INET / AF_INET6) of an open socket fd, or
// AF_UNSPEC if it cannot be determined. Works on an open-but-unbound socket:
// getsockname reports ss_family even before bind/connect. Uses SockaddrStorage
// for portable sockaddr/socklen handling (Windows uses int, POSIX socklen_t).
int GetFdFamily(SocketDescriptor fd) {
  if (fd == kInvalidSocket)
    return AF_UNSPEC;
  SockaddrStorage storage;
  if (getsockname(fd, storage.addr(), &storage.addr_len) != 0)
    return AF_UNSPEC;
  return storage.addr()->sa_family;
}

// Binds an already-open, not-yet-connected fd to the chosen interface.
// `family` is the socket's address family (AF_INET / AF_INET6), so that on
// Windows/Apple/BSD we require *the matching* per-family setsockopt to succeed
// rather than accepting "either family bound" (which would let a socket leak
// out the physical NIC when only the irrelevant family's bind happened to
// succeed). AF_UNSPEC means "unknown" and falls back to accepting either.
// Returns a net error.
int BindFdToInterface(uint32_t if_index,
                      const std::string& if_name,
                      SocketDescriptor fd,
                      int family) {
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
  // A v4 socket cannot take IPV6_UNICAST_IF (and vice versa); only demand the
  // bind matching this socket's family. NOTE: on Windows IP(V6)_UNICAST_IF is a
  // routing *hint*, not a hard bind like Linux SO_BINDTODEVICE -- the stack may
  // still egress via another NIC based on connectivity. See TUN README.
  bool ok = (family == AF_INET)    ? (rv4 == 0)
            : (family == AF_INET6) ? (rv6 == 0)
                                   : (rv4 == 0 || rv6 == 0);
  if (!ok) {
    PLOG(ERROR) << "bind-interface: IP(V6)_UNICAST_IF failed (family=" << family
                << ")";
    return ERR_FAILED;
  }
#elif BUILDFLAG(IS_APPLE) || BUILDFLAG(IS_BSD)
  int idx = static_cast<int>(if_index);
  int rv4 = setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &idx, sizeof(idx));
  int rv6 = setsockopt(fd, IPPROTO_IPV6, IPV6_BOUND_IF, &idx, sizeof(idx));
  bool ok = (family == AF_INET)    ? (rv4 == 0)
            : (family == AF_INET6) ? (rv6 == 0)
                                   : (rv4 == 0 || rv6 == 0);
  if (!ok) {
    PLOG(ERROR) << "bind-interface: IP(V6)_BOUND_IF failed (family=" << family
                << ")";
    return ERR_FAILED;
  }
#else  // Linux / Android
  // SO_BINDTODEVICE binds by name and covers both v4 and v6 with a single hard
  // bind (traffic to a down/unreachable NIC is black-holed, never leaked).
  // Needs CAP_NET_RAW. `family` is unused here.
  (void)family;
  if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, if_name.c_str(),
                 static_cast<socklen_t>(if_name.size())) != 0) {
    PLOG(ERROR) << "bind-interface: SO_BINDTODEVICE(" << if_name
                << ") failed (needs CAP_NET_RAW)";
    return ERR_FAILED;
  }
#endif
  return OK;
}

// A UDPClientSocket that binds its fd to the chosen interface before connecting.
// UDPClientSocket has no before-connect hook, so we create the platform socket
// ourselves, bind it, and hand it to the base via AdoptOpenedSocket(); the base
// Connect() then skips Open() and connects on our already-bound fd. This closes
// the leak where a `quic://` upstream would egress raw UDP through the physical
// NIC / TUN without honoring bind-interface.
class BindToInterfaceUDPClientSocket : public UDPClientSocket {
 public:
  // Note: qualify net::NetLog because UDPClientSocket has a NetLog() method,
  // which otherwise shadows the type name inside this class scope.
  BindToInterfaceUDPClientSocket(DatagramSocket::BindType bind_type,
                                 net::NetLog* net_log,
                                 const NetLogSource& source,
                                 uint32_t if_index,
                                 std::string if_name)
      : UDPClientSocket(bind_type, net_log, source),
        if_index_(if_index),
        if_name_(std::move(if_name)) {}

  int Connect(const IPEndPoint& address) override {
    int rv = OpenAndBind(address.GetFamily());
    if (rv != OK)
      return rv;
    return UDPClientSocket::Connect(address);
  }

  int ConnectAsync(const IPEndPoint& address,
                   CompletionOnceCallback callback) override {
    int rv = OpenAndBind(address.GetFamily());
    if (rv != OK)
      return rv;
    return UDPClientSocket::ConnectAsync(address, std::move(callback));
  }

 private:
  // Creates a platform UDP socket for `family`, binds it to the interface, and
  // adopts it so the base class connects on the bound fd instead of opening a
  // fresh unbound one.
  int OpenAndBind(AddressFamily family) {
    if (if_index_ == 0)
      return OK;  // binding disabled; base class opens normally
    int af = ConvertAddressFamily(family);
    SocketDescriptor fd = CreatePlatformSocket(af, SOCK_DGRAM, IPPROTO_UDP);
    if (fd == kInvalidSocket) {
      PLOG(ERROR) << "bind-interface(udp): socket() failed";
      return ERR_FAILED;
    }
    int rv = BindFdToInterface(if_index_, if_name_, fd, af);
    if (rv != OK) {
#if BUILDFLAG(IS_WIN)
      closesocket(fd);
#else
      close(fd);
#endif
      return rv;
    }
    rv = AdoptOpenedSocket(family, fd);
    if (rv != OK) {
      PLOG(ERROR) << "bind-interface(udp): AdoptOpenedSocket failed";
      // AdoptOpenedSocket closes the fd on failure.
      return rv;
    }
    return OK;
  }

  uint32_t if_index_;
  std::string if_name_;
};

}  // namespace

BindToInterfaceClientSocketFactory::BindToInterfaceClientSocketFactory(
    const std::string& interface_name) {
  interface_index_ = ResolveInterface(interface_name, &resolved_name_);
  LOG(INFO) << "bind-interface: requested '" << interface_name
            << "' -> using '" << resolved_name_ << "' (index "
            << interface_index_ << ")";
}

std::unique_ptr<DatagramClientSocket>
BindToInterfaceClientSocketFactory::CreateDatagramClientSocket(
    DatagramSocket::BindType bind_type,
    NetLog* net_log,
    const NetLogSource& source) {
  if (interface_index_ == 0) {
    // Binding disabled / unresolved: behave like the default factory.
    return ClientSocketFactory::GetDefaultFactory()->CreateDatagramClientSocket(
        bind_type, net_log, source);
  }
  return std::make_unique<BindToInterfaceUDPClientSocket>(
      bind_type, net_log, source, interface_index_, resolved_name_);
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
  std::string name = resolved_name_;
  raw->SetBeforeConnectCallback(base::BindRepeating(
      [](uint32_t if_index, const std::string& if_name,
         TCPClientSocket* sock) -> int {
        SocketDescriptor fd = sock->SocketDescriptorForTesting();
        return BindFdToInterface(if_index, if_name, fd, GetFdFamily(fd));
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
