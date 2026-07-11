// Copyright 2018 The Chromium Authors. All rights reserved.
// Copyright 2018 klzgrad <kizdiv@gmail.com>. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Portions Copyright 2026 justinwoo280 <justinwoo280@gmail.com>,
// governed by the same BSD-style license (see the LICENSE file).

#include "net/tools/naive/naive_proxy.h"

#include <string>
#include <utility>

#include "base/functional/bind.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/task/single_thread_task_runner.h"
#include "base/time/time.h"
#include "build/build_config.h"
#include "net/base/load_flags.h"
#include "net/base/net_errors.h"
#include "net/http/http_network_session.h"
#include "net/proxy_resolution/configured_proxy_resolution_service.h"
#include "net/proxy_resolution/proxy_config.h"
#include "net/proxy_resolution/proxy_list.h"
#include "net/socket/client_socket_pool_manager.h"
#include "net/socket/server_socket.h"
#include "net/socket/stream_socket.h"
#include "net/tools/naive/http_proxy_server_socket.h"
#include "net/tools/naive/naive_proxy_delegate.h"
#include "net/tools/naive/socks5_server_socket.h"

namespace net {
namespace {
constexpr base::TimeDelta kIdleCheckPeriod = base::Minutes(1);
}  // namespace

NaiveProxy::Tunnel::Tunnel() = default;
NaiveProxy::Tunnel::~Tunnel() = default;
NaiveProxy::PendingSocks5::PendingSocks5() = default;
NaiveProxy::PendingSocks5::~PendingSocks5() = default;

NaiveProxy::NaiveProxy(std::unique_ptr<ServerSocket> listen_socket,
                       ClientProtocol protocol,
                       const std::string& listen_user,
                       const std::string& listen_pass,
                       int concurrency,
                       int tunnel_timeout,
                       int idle_timeout,
                       RedirectResolver* resolver,
                       HttpNetworkSession* session,
                       const NetworkTrafficAnnotationTag& traffic_annotation,
                       const std::vector<PaddingType>& supported_padding_types)
    : listen_socket_(std::move(listen_socket)),
      protocol_(protocol),
      listen_user_(listen_user),
      listen_pass_(listen_pass),
      concurrency_(concurrency),
      tunnel_timeout_(base::Seconds(tunnel_timeout)),
      idle_timeout_(base::Seconds(idle_timeout)),
      resolver_(resolver),
      session_(session),
      net_log_(
          NetLogWithSource::Make(session->net_log(), NetLogSourceType::NONE)),
      next_id_(0),
      next_state_(State::kAccept),
      tunnels_(concurrency),
      traffic_annotation_(traffic_annotation),
      supported_padding_types_(supported_padding_types) {
  const auto& proxy_config = static_cast<ConfiguredProxyResolutionService*>(
                                 session_->proxy_resolution_service())
                                 ->config();
  DCHECK(proxy_config);
  const ProxyList& proxy_list =
      proxy_config.value().value().proxy_rules().single_proxies;
  DCHECK(!proxy_list.IsEmpty());
  proxy_info_.UseProxyList(proxy_list);
  proxy_info_.set_traffic_annotation(
      net::MutableNetworkTrafficAnnotationTag(traffic_annotation_));
  if (!proxy_info_.is_direct()) {
    const ProxyChain& proxy_chain = proxy_info_.proxy_chain();
    std::tie(last_proxy_partial_chain_, last_proxy_server_) =
        proxy_chain.SplitLast();
  }

  DCHECK(listen_socket_);
  // Start accepting connections in next run loop in case when delegate is not
  // ready to get callbacks.
  io_callback_ = base::BindRepeating(&NaiveProxy::OnIOComplete,
                                     weak_ptr_factory_.GetWeakPtr());
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE, base::BindOnce(&NaiveProxy::OnIOComplete,
                                weak_ptr_factory_.GetWeakPtr(), OK));

  cleanup_timer_.Start(FROM_HERE, kIdleCheckPeriod, this,
                       &NaiveProxy::CleanUpIdleConnections);
}

NaiveProxy::~NaiveProxy() = default;

void NaiveProxy::OnIOComplete(int result) {
  DCHECK_NE(next_state_, State::kNone);
  int rv = DoLoop(result);
  if (rv != ERR_IO_PENDING) {
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE, base::BindOnce(&NaiveProxy::OnIOComplete,
                                  weak_ptr_factory_.GetWeakPtr(), OK));
  }
}

int NaiveProxy::DoLoop(int last_io_result) {
  DCHECK_NE(next_state_, State::kNone);
  int rv = last_io_result;
  do {
    State state = next_state_;
    next_state_ = State::kNone;
    switch (state) {
      case State::kAccept:
        DCHECK_EQ(OK, rv);
        rv = DoAccept();
        break;
      case State::kAcceptComplete:
        rv = DoAcceptComplete(rv);
        break;
      case State::kPreamble:
        DCHECK_EQ(OK, rv);
        rv = DoPreamble();
        break;
      case State::kPreambleComplete:
        rv = DoPreambleComplete(rv);
        break;
      case State::kConnect:
        DCHECK_EQ(OK, rv);
        rv = DoConnect();
        break;
      default:
        rv = ERR_UNEXPECTED;
        break;
    }
  } while (rv != ERR_IO_PENDING && next_state_ != State::kNone);
  return rv;
}

int NaiveProxy::DoAccept() {
  next_state_ = State::kAcceptComplete;
  return listen_socket_->Accept(&accepted_socket_, io_callback_);
}

int NaiveProxy::DoAcceptComplete(int result) {
  if (result != OK) {
    next_state_ = State::kAccept;
    LOG(ERROR) << "Accept error: " << ErrorToShortString(result);
    // This accept error is ignored to start the next accept.
    return OK;
  }

  Tunnel& tunnel = tunnels_[next_id_ % concurrency_];
  base::TimeTicks now = base::TimeTicks::Now();
  if (IsSessionCapable()) {
    if (tunnel.deadline.is_null()) {
      tunnel.deadline = now + tunnel_timeout_;
      next_state_ = State::kPreamble;
    } else if (now > tunnel.deadline) {
      tunnel.nak = NetworkAnonymizationKey::CreateTransient();
      tunnel.deadline = now + tunnel_timeout_;
      tunnel.url_getter.reset();
      next_state_ = State::kPreamble;
    } else {
      DCHECK(tunnel.url_getter != nullptr);
      tunnel.url_getter->StartOne();
      next_state_ = State::kConnect;
    }
  } else {
    next_state_ = State::kConnect;
  }
  return OK;
}

// Possible exit states: State::kAccept, State::kPreambleComplete
int NaiveProxy::DoPreamble() {
  Tunnel& tunnel = tunnels_[next_id_ % concurrency_];
  DCHECK(WillCreateSession(tunnel.nak));
  tunnel.url_getter = std::make_unique<PreambleGetter>(proxy_info_, session_,
                                                       tunnel.nak, net_log_);
  next_state_ = State::kPreambleComplete;
  return tunnel.url_getter->Start(io_callback_);
}

int NaiveProxy::DoPreambleComplete(int result) {
  if (result != OK) {
    LOG(WARNING) << "Preamble error: " << ErrorToShortString(result);
    // Preamble error doesn't prevent Connect().
  }
  next_state_ = State::kConnect;
  return OK;
}

int NaiveProxy::DoConnect() {
  auto negotiated_client_padding =
      std::make_unique<PaddingType>(PaddingType::kNone);

  // Once accepted_socket_ is moved, the next Accept can start.
  next_state_ = State::kAccept;

  if (protocol_ == ClientProtocol::kSocks5) {
    // For SOCKS5, do the handshake ourselves to detect UDP ASSOCIATE
    // before deciding between NaiveConnection (TCP) and NaiveUdpConnection (UDP).
    unsigned int id = next_id_++;
    auto socks5_socket = std::make_unique<Socks5ServerSocket>(
        std::move(accepted_socket_), listen_user_, listen_pass_,
        traffic_annotation_);

    auto pending = std::make_unique<PendingSocks5>();
    pending->socket = std::move(socks5_socket);
    pending->nak = tunnels_[id % concurrency_].nak;

    Socks5ServerSocket* socket_ptr = pending->socket.get();
    pending_socks5_[id] = std::move(pending);

    int rv = socket_ptr->Connect(
        base::BindOnce(&NaiveProxy::OnSocks5HandshakeComplete,
                       weak_ptr_factory_.GetWeakPtr(), id));
    if (rv == ERR_IO_PENDING) {
      return OK;
    }
    OnSocks5HandshakeComplete(id, rv);
    return OK;
  }

  std::unique_ptr<StreamSocket> socket;
  if (protocol_ == ClientProtocol::kHttp) {
    socket = std::make_unique<HttpProxyServerSocket>(
        std::move(accepted_socket_), listen_user_, listen_pass_,
        negotiated_client_padding.get(), traffic_annotation_,
        supported_padding_types_);
  } else if (protocol_ == ClientProtocol::kRedir) {
    socket = std::move(accepted_socket_);
  } else {
    return OK;
  }

  const Tunnel& tunnel = tunnels_[next_id_ % concurrency_];
  auto connection_ptr = std::make_unique<NaiveConnection>(
      next_id_, protocol_, std::move(negotiated_client_padding), proxy_info_,
      resolver_, session_, tunnel.nak, net_log_, std::move(socket),
      traffic_annotation_);
  auto* connection = connection_ptr.get();
  connection_by_id_[connection->id()] = std::move(connection_ptr);

  ++next_id_;

  int result = connection->Connect(
      base::BindOnce(&NaiveProxy::OnConnectComplete,
                     weak_ptr_factory_.GetWeakPtr(), connection->id()));
  if (result == ERR_IO_PENDING) {
    // Connect result doesn't prevent the next Accept
    return OK;
  }
  HandleConnectResult(connection, result);
  return OK;
}

void NaiveProxy::OnConnectComplete(unsigned int connection_id, int result) {
  auto* connection = FindConnection(connection_id);
  if (!connection) {
    return;
  }
  HandleConnectResult(connection, result);
}

void NaiveProxy::HandleConnectResult(NaiveConnection* connection, int result) {
  if (result != OK) {
    Close(connection->id(), result);
    return;
  }
  DoRun(connection);
}

void NaiveProxy::DoRun(NaiveConnection* connection) {
  int result = connection->Run(base::BindOnce(&NaiveProxy::OnRunComplete,
                                              weak_ptr_factory_.GetWeakPtr(),
                                              connection->id()));
  if (result == ERR_IO_PENDING) {
    return;
  }
  HandleRunResult(connection, result);
}

void NaiveProxy::OnRunComplete(unsigned int connection_id, int result) {
  auto* connection = FindConnection(connection_id);
  if (!connection) {
    return;
  }
  HandleRunResult(connection, result);
}

void NaiveProxy::HandleRunResult(NaiveConnection* connection, int result) {
  Close(connection->id(), result);
}

void NaiveProxy::Close(unsigned int connection_id, int reason) {
  auto it = connection_by_id_.find(connection_id);
  if (it == connection_by_id_.end()) {
    return;
  }

  LOG(INFO) << "Connection " << connection_id
            << " closed: " << ErrorToShortString(reason);

  // The call stack might have callbacks which still have the pointer of
  // connection. Instead of referencing connection with ID all the time,
  // destroys the connection in next run loop to make sure any pending
  // callbacks in the call stack return.
  base::SingleThreadTaskRunner::GetCurrentDefault()->DeleteSoon(
      FROM_HERE, std::move(it->second));
  connection_by_id_.erase(it);
}

void NaiveProxy::OnSocks5HandshakeComplete(unsigned int connection_id,
                                            int result) {
  auto it = pending_socks5_.find(connection_id);
  if (it == pending_socks5_.end()) {
    return;
  }

  auto pending = std::move(it->second);
  pending_socks5_.erase(it);

  if (result != OK) {
    LOG(WARNING) << "SOCKS5 handshake failed for connection " << connection_id
                 << ": " << ErrorToShortString(result);
    return;
  }

  if (pending->socket->is_udp_associate()) {
    // UDP ASSOCIATE: take UDP relay socket + TCP control socket.
    auto udp_relay = pending->socket->TakeUdpRelaySocket();
    auto control_socket =
        std::unique_ptr<StreamSocket>(std::move(pending->socket));

    auto udp_conn = std::make_unique<NaiveUdpConnection>(
        connection_id, std::move(udp_relay), std::move(control_socket),
        proxy_info_, session_, pending->nak, net_log_, traffic_annotation_);
    auto* conn_ptr = udp_conn.get();
    udp_connection_by_id_[connection_id] = std::move(udp_conn);

    int rv = conn_ptr->Connect(
        base::BindOnce(&NaiveProxy::OnUdpConnectComplete,
                       weak_ptr_factory_.GetWeakPtr(), connection_id));
    if (rv == ERR_IO_PENDING) {
      return;
    }
    HandleUdpConnectResult(conn_ptr, rv);
  } else {
    // TCP CONNECT: pass already-connected Socks5ServerSocket to NaiveConnection.
    auto negotiated_padding = std::make_unique<PaddingType>(PaddingType::kNone);
    auto connection_ptr = std::make_unique<NaiveConnection>(
        connection_id, protocol_, std::move(negotiated_padding), proxy_info_,
        resolver_, session_, pending->nak, net_log_,
        std::move(pending->socket), traffic_annotation_);
    auto* connection = connection_ptr.get();
    connection_by_id_[connection_id] = std::move(connection_ptr);

    int rv = connection->Connect(
        base::BindOnce(&NaiveProxy::OnConnectComplete,
                       weak_ptr_factory_.GetWeakPtr(), connection_id));
    if (rv == ERR_IO_PENDING) {
      return;
    }
    HandleConnectResult(connection, rv);
  }
}

void NaiveProxy::OnUdpConnectComplete(unsigned int connection_id, int result) {
  auto* conn = FindUdpConnection(connection_id);
  if (!conn) {
    return;
  }
  HandleUdpConnectResult(conn, result);
}

void NaiveProxy::HandleUdpConnectResult(NaiveUdpConnection* conn, int result) {
  if (result != OK) {
    CloseUdp(conn->id(), result);
    return;
  }
  DoRunUdp(conn);
}

void NaiveProxy::DoRunUdp(NaiveUdpConnection* conn) {
  int result = conn->Run(base::BindOnce(&NaiveProxy::OnUdpRunComplete,
                                        weak_ptr_factory_.GetWeakPtr(),
                                        conn->id()));
  if (result == ERR_IO_PENDING) {
    return;
  }
  HandleUdpRunResult(conn, result);
}

void NaiveProxy::OnUdpRunComplete(unsigned int connection_id, int result) {
  auto* conn = FindUdpConnection(connection_id);
  if (!conn) {
    return;
  }
  HandleUdpRunResult(conn, result);
}

void NaiveProxy::HandleUdpRunResult(NaiveUdpConnection* conn, int result) {
  CloseUdp(conn->id(), result);
}

void NaiveProxy::CloseUdp(unsigned int connection_id, int reason) {
  auto it = udp_connection_by_id_.find(connection_id);
  if (it == udp_connection_by_id_.end()) {
    return;
  }

  LOG(INFO) << "UoT connection " << connection_id
            << " closed: " << ErrorToShortString(reason);

  base::SingleThreadTaskRunner::GetCurrentDefault()->DeleteSoon(
      FROM_HERE, std::move(it->second));
  udp_connection_by_id_.erase(it);
}

NaiveUdpConnection* NaiveProxy::FindUdpConnection(unsigned int connection_id) {
  auto it = udp_connection_by_id_.find(connection_id);
  if (it == udp_connection_by_id_.end()) {
    return nullptr;
  }
  return it->second.get();
}

NaiveConnection* NaiveProxy::FindConnection(unsigned int connection_id) {
  auto it = connection_by_id_.find(connection_id);
  if (it == connection_by_id_.end()) {
    return nullptr;
  }
  return it->second.get();
}

NaiveProxyDelegate* NaiveProxy::naive_proxy_delegate() const {
  auto* proxy_delegate =
      static_cast<NaiveProxyDelegate*>(session_->context().proxy_delegate);
  DCHECK(proxy_delegate);
  return proxy_delegate;
}

bool NaiveProxy::IsSessionCapable() const {
  if (proxy_info_.is_direct()) {
    return false;
  }
  // TODO(klzgrad): HTTP/1 https proxy will fail
  return last_proxy_server_.is_secure_http_like();
}

bool NaiveProxy::WillCreateSession(const NetworkAnonymizationKey& nak) const {
  if (last_proxy_server_.is_https()) {
    SpdySessionKey key(last_proxy_server_.host_port_pair(),
                       PRIVACY_MODE_DISABLED, last_proxy_partial_chain_,
                       SessionUsage::kProxy, SocketTag(), nak,
                       SecureDnsPolicy::kDisable,
                       /*disable_cert_verification_network_fetches=*/true);
    return !session_->spdy_session_pool()->FindAvailableSession(
        key, /*enable_ip_based_pooling_for_h2=*/false,
        /*is_websocket=*/false, net_log_);
  }
  if (last_proxy_server_.is_quic()) {
    QuicSessionKey key(
        last_proxy_server_.host_port_pair(), PRIVACY_MODE_DISABLED,
        last_proxy_partial_chain_, SessionUsage::kProxy, SocketTag(), nak,
        SecureDnsPolicy::kDisable, /*require_dns_https_alpn=*/false,
        /*disable_cert_verification_network_fetches=*/true);
    url::SchemeHostPort destination("https", last_proxy_server_.GetHost(),
                                    last_proxy_server_.GetPort(),
                                    url::SchemeHostPort::ALREADY_CANONICALIZED);
    return !session_->quic_session_pool()->CanUseExistingSession(key,
                                                                 destination);
  }
  return false;
}

void NaiveProxy::CleanUpIdleConnections() {
  std::vector<NaiveConnection*> idle_conns;
  std::vector<NaiveUdpConnection*> idle_udp_conns;
  base::TimeTicks now = base::TimeTicks::Now();
  for (const auto& [id, conn] : connection_by_id_) {
    base::TimeDelta idle = now - conn->GetLastWriteTime();
    base::TimeDelta age = now - conn->GetCreationTime();
    if (idle > idle_timeout_ || age > tunnel_timeout_) {
      idle_conns.push_back(conn.get());
    }
  }
  for (const auto& [id, conn] : udp_connection_by_id_) {
    base::TimeDelta idle = now - conn->GetLastWriteTime();
    base::TimeDelta age = now - conn->GetCreationTime();
    if (idle > idle_timeout_ || age > tunnel_timeout_) {
      idle_udp_conns.push_back(conn.get());
    }
  }
  for (NaiveConnection* conn : idle_conns) {
    conn->Disconnect();
  }
  for (NaiveUdpConnection* conn : idle_udp_conns) {
    conn->Disconnect();
  }
  session_->CloseIdleConnections("Rotate old tunnels");
}
}  // namespace net
