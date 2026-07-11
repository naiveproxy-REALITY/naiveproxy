// Copyright 2026 justinwoo280 <justinwoo280@gmail.com>. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#ifndef NET_TOOLS_NAIVE_NAIVE_UDP_CONNECTION_H_
#define NET_TOOLS_NAIVE_NAIVE_UDP_CONNECTION_H_

#include <memory>
#include <string>

#include "base/memory/weak_ptr.h"
#include "net/base/completion_once_callback.h"
#include "net/base/completion_repeating_callback.h"
#include "net/base/host_port_pair.h"
#include "net/base/ip_endpoint.h"
#include "net/base/network_anonymization_key.h"
#include "net/base/network_isolation_key.h"
#include "net/log/net_log_with_source.h"
#include "net/proxy_resolution/proxy_info.h"
#include "net/socket/stream_socket.h"
#include "net/socket/udp_server_socket.h"
#include "net/tools/naive/naive_padding_socket.h"
#include "net/tools/naive/naive_protocol.h"
#include "net/tools/naive/naive_uot_framer.h"

namespace net {

class ClientSocketHandle;
class HttpNetworkSession;
class IOBuffer;
struct NetworkTrafficAnnotationTag;

// NaiveUdpConnection bridges a local SOCKS5 UDP relay socket to a remote
// H2 CONNECT tunnel using UoT v2 framing.
//
// Lifecycle:
//   1. NaiveProxy does SOCKS5 UDP ASSOCIATE handshake via Socks5ServerSocket
//   2. Takes the UDP relay socket + TCP control socket
//   3. Creates NaiveUdpConnection with both
//   4. Connect() establishes H2 CONNECT to UoT magic address
//   5. Run() starts bidirectional relay:
//      - Client→Server: UDP packet → parse SOCKS5 header → UoT frame → H2
//      - Server→Client: H2 → UoT frame → wrap SOCKS5 header → UDP packet
//   6. Tears down when TCP control socket closes or either direction errors
class NaiveUdpConnection {
 public:
  NaiveUdpConnection(unsigned int id,
                     std::unique_ptr<UDPServerSocket> udp_relay,
                     std::unique_ptr<StreamSocket> control_socket,
                     const ProxyInfo& proxy_info,
                     HttpNetworkSession* session,
                     const NetworkAnonymizationKey& network_anonymization_key,
                     const NetLogWithSource& net_log,
                     const NetworkTrafficAnnotationTag& traffic_annotation);
  ~NaiveUdpConnection();
  NaiveUdpConnection(const NaiveUdpConnection&) = delete;
  NaiveUdpConnection& operator=(const NaiveUdpConnection&) = delete;

  unsigned int id() const { return id_; }
  int Connect(CompletionOnceCallback callback);
  void Disconnect();
  int Run(CompletionOnceCallback callback);
  base::TimeTicks GetCreationTime() const { return created_at_; }
  base::TimeTicks GetLastWriteTime() const { return last_write_time_; }

  // Public for unit testing.
  static std::string BuildSocks5UdpHeader(const HostPortPair& dest);
  static bool ParseSocks5UdpPacket(const uint8_t* data, size_t len,
                                    HostPortPair& dest,
                                    std::string_view& payload);

 private:
  void StartConnectServer();
  void OnConnectServerComplete(int result);
  void StartClientRead();
  void OnClientReadComplete(int result);
  void StartServerRead();
  void OnServerReadComplete(int result);
  void StartControlRead();
  void OnControlReadComplete(int result);
  void SendUotHandshake(const HostPortPair& dest);
  void OnHandshakeSent(int result);
  void SendToClient(scoped_refptr<IOBuffer> buf, int len);
  void OnSendToClientComplete(int result);
  void MaybeComplete();
  std::optional<PaddingType> GetServerPaddingType() const;
  int ServerWrite(IOBuffer* buf, int buf_len, CompletionOnceCallback callback);
  int ServerRead(IOBuffer* buf, int buf_len, CompletionOnceCallback callback);

  unsigned int id_;
  std::unique_ptr<UDPServerSocket> udp_relay_;
  std::unique_ptr<StreamSocket> control_socket_;
  const ProxyInfo& proxy_info_;
  HttpNetworkSession* session_;
  NetworkAnonymizationKey network_anonymization_key_;
  const NetLogWithSource& net_log_;
  const NetworkTrafficAnnotationTag& traffic_annotation_;

  CompletionRepeatingCallback io_callback_;
  CompletionOnceCallback connect_callback_;
  CompletionOnceCallback run_callback_;

  std::unique_ptr<ClientSocketHandle> server_socket_handle_;
  std::unique_ptr<NaivePaddingSocket> server_padding_socket_;
  bool connected_ = false;

  NaiveUotFramer uot_framer_;
  bool handshake_sent_ = false;
  bool pending_payload_valid_ = false;
  HostPortPair pending_dest_;

  scoped_refptr<IOBuffer> client_read_buf_;
  IPEndPoint client_addr_;
  bool client_addr_known_ = false;
  scoped_refptr<IOBuffer> server_read_buf_;
  scoped_refptr<IOBuffer> control_read_buf_;
  std::string pending_payload_;

  bool client_done_ = false;
  bool server_done_ = false;
  bool control_done_ = false;

  base::TimeTicks created_at_;
  base::TimeTicks last_write_time_;

  base::WeakPtrFactory<NaiveUdpConnection> weak_ptr_factory_{this};
};

}  // namespace net
#endif  // NET_TOOLS_NAIVE_NAIVE_UDP_CONNECTION_H_
