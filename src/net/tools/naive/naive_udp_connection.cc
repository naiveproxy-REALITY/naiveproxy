// Copyright 2024 NaiveProxy-REALITY contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include "net/tools/naive/naive_udp_connection.h"

#include <array>
#include <cstring>
#include <utility>

#include "base/compiler_specific.h"
#include "base/containers/span.h"
#include "base/logging.h"
#include "base/numerics/byte_conversions.h"
#include "base/sys_byteorder.h"
#include "net/base/host_port_pair.h"
#include "net/base/ip_address.h"
#include "net/base/load_flags.h"
#include "net/base/net_errors.h"
#include "net/http/http_network_session.h"
#include "net/socket/client_socket_handle.h"
#include "net/socket/client_socket_pool_manager.h"
#include "net/socket/stream_socket.h"
#include "net/tools/naive/naive_proxy_delegate.h"
#include "url/scheme_host_port.h"

namespace net {

namespace {
constexpr int kUdpBufSize = 65536;
constexpr int kTcpBufSize = 65536;
constexpr int kControlBufSize = 64;
constexpr uint8_t kAtypIPv4 = 0x01;
constexpr uint8_t kAtypIPv6 = 0x04;
constexpr uint8_t kAtypDomain = 0x03;
}  // namespace

NaiveUdpConnection::NaiveUdpConnection(
    unsigned int id,
    std::unique_ptr<UDPServerSocket> udp_relay,
    std::unique_ptr<StreamSocket> control_socket,
    const ProxyInfo& proxy_info,
    HttpNetworkSession* session,
    const NetworkAnonymizationKey& nak,
    const NetLogWithSource& net_log,
    const NetworkTrafficAnnotationTag& traffic_annotation)
    : id_(id),
      udp_relay_(std::move(udp_relay)),
      control_socket_(std::move(control_socket)),
      proxy_info_(proxy_info),
      session_(session),
      network_anonymization_key_(nak),
      net_log_(net_log),
      traffic_annotation_(traffic_annotation),
      created_at_(base::TimeTicks::Now()),
      last_write_time_(created_at_) {
  io_callback_ = base::BindRepeating(&NaiveUdpConnection::OnConnectServerComplete,
                                     weak_ptr_factory_.GetWeakPtr());
}

NaiveUdpConnection::~NaiveUdpConnection() { Disconnect(); }

void NaiveUdpConnection::Disconnect() {
  if (udp_relay_) udp_relay_->Close();
  if (control_socket_) control_socket_->Disconnect();
  if (server_socket_handle_ && server_socket_handle_->socket())
    server_socket_handle_->socket()->Disconnect();
  server_padding_socket_.reset();
  connected_ = false;
  client_done_ = true;
  server_done_ = true;
  control_done_ = true;
}

// ---- SOCKS5 UDP header helpers ----

// static
std::string NaiveUdpConnection::BuildSocks5UdpHeader(const HostPortPair& dest) {
  std::string h;
  h.push_back(0x00);  // RSV (2 bytes, per RFC 1928)
  h.push_back(0x00);
  h.push_back(0x00);  // FRAG
  IPAddress ip;
  if (ip.AssignFromIPLiteral(dest.host())) {
    if (ip.IsIPv4()) {
      h.push_back(kAtypIPv4);
      h.append(reinterpret_cast<const char*>(ip.bytes().data()), 4);
    } else {
      h.push_back(kAtypIPv6);
      h.append(reinterpret_cast<const char*>(ip.bytes().data()), 16);
    }
  } else {
    h.push_back(kAtypDomain);
    h.push_back(static_cast<uint8_t>(dest.host().size()));
    h.append(dest.host());
  }
  uint16_t port_be = base::HostToNet16(dest.port());
  h.append(reinterpret_cast<const char*>(&port_be), 2);
  return h;
}

// static
bool NaiveUdpConnection::ParseSocks5UdpPacket(const uint8_t* data, size_t len,
                                               HostPortPair& dest,
                                               std::string_view& payload) {
  if (len < 4) return false;
  if (data[0] != 0 || data[1] != 0 || data[2] != 0) return false;
  uint8_t atyp = data[3];
  size_t off = 4;
  // Bounds are validated per-case above; wrap the raw-pointer accesses in
  // UNSAFE_BUFFERS as required by Chromium's spanification rules.
  auto read_port_be = [&](size_t at) -> uint16_t {
    uint8_t bytes[2];
    UNSAFE_BUFFERS(bytes[0] = data[at]; bytes[1] = data[at + 1]);
    return base::U16FromBigEndian(bytes);
  };
  switch (atyp) {
    case kAtypIPv4: {
      if (len < off + 6) return false;
      std::array<uint8_t, 4> b;
      UNSAFE_BUFFERS(std::memcpy(b.data(), data + off, 4));
      IPAddress ip(b);
      dest = HostPortPair::FromIPEndPoint(IPEndPoint(ip, read_port_be(off + 4)));
      off += 6;
      break;
    }
    case kAtypIPv6: {
      if (len < off + 18) return false;
      std::array<uint8_t, 16> b;
      UNSAFE_BUFFERS(std::memcpy(b.data(), data + off, 16));
      IPAddress ip(b);
      dest =
          HostPortPair::FromIPEndPoint(IPEndPoint(ip, read_port_be(off + 16)));
      off += 18;
      break;
    }
    case kAtypDomain: {
      if (len < off + 1) return false;
      uint8_t dlen = data[off++];
      if (len < off + dlen + 2) return false;
      std::string host;
      UNSAFE_BUFFERS(
          host.assign(reinterpret_cast<const char*>(data + off), dlen));
      dest = HostPortPair(host, read_port_be(off + dlen));
      off += dlen + 2;
      break;
    }
    default:
      return false;
  }
  payload =
      std::string_view(reinterpret_cast<const char*>(data + off), len - off);
  return true;
}

// ---- Phase 1: Connect H2 CONNECT to UoT magic address ----

int NaiveUdpConnection::Connect(CompletionOnceCallback callback) {
  DCHECK(!connect_callback_);
  LOG(ERROR) << "UoT DIAG conn " << id_ << " Connect() entered";
  connect_callback_ = std::move(callback);
  StartConnectServer();
  return ERR_IO_PENDING;
}

void NaiveUdpConnection::StartConnectServer() {
  url::SchemeHostPort endpoint("http", kUotMagicAddress, 0);
  server_socket_handle_ = std::make_unique<ClientSocketHandle>();

  LOG(ERROR) << "UoT DIAG conn " << id_ << " connecting H2 CONNECT to "
             << endpoint.Serialize() << " valid=" << endpoint.IsValid()
             << " via " << proxy_info_.ToDebugString()
             << " is_direct=" << proxy_info_.is_direct()
             << " session=" << (session_ != nullptr);

  int rv = InitSocketHandleForHttpRequest(
      std::move(endpoint), LOAD_IGNORE_LIMITS, MAXIMUM_PRIORITY, session_,
      proxy_info_, {}, PRIVACY_MODE_DISABLED, network_anonymization_key_,
      SecureDnsPolicy::kDisable, SocketTag(), handles::kInvalidNetworkHandle,
      net_log_, server_socket_handle_.get(), io_callback_,
      ClientSocketPool::ProxyAuthCallback());

  LOG(ERROR) << "UoT DIAG conn " << id_
             << " InitSocketHandleForHttpRequest rv=" << rv;
  if (rv != ERR_IO_PENDING) {
    OnConnectServerComplete(rv);
  }
}

void NaiveUdpConnection::OnConnectServerComplete(int result) {
  if (result < 0) {
    LOG(ERROR) << "UoT conn " << id_ << " connect failed: " << result;
    std::move(connect_callback_).Run(result);
    return;
  }
  connected_ = true;

  // Wrap server socket in NaivePaddingSocket for padding support.
  // The padding type is negotiated between NaiveProxy client and proxy server
  // via HTTP headers. If kNone, padding socket is pass-through. If kVariant1,
  // the first 8 frames are padded — without this, UoT frames would be
  // misinterpreted as padding frames, causing data corruption.
  std::optional<PaddingType> padding_type = GetServerPaddingType();
  if (padding_type.has_value()) {
    server_padding_socket_ = std::make_unique<NaivePaddingSocket>(
        server_socket_handle_->socket(), *padding_type, Direction::kServer);
  } else {
    // No padding info yet — use kNone (pass-through).
    server_padding_socket_ = std::make_unique<NaivePaddingSocket>(
        server_socket_handle_->socket(), PaddingType::kNone, Direction::kServer);
  }

  LOG(INFO) << "UoT conn " << id_ << " H2 CONNECT established";
  std::move(connect_callback_).Run(OK);
}

// ---- Phase 2: Bidirectional relay ----

int NaiveUdpConnection::Run(CompletionOnceCallback callback) {
  DCHECK(connected_);
  LOG(ERROR) << "UoT DIAG conn " << id_ << " Run() udp_relay valid="
             << (udp_relay_ != nullptr);
  run_callback_ = std::move(callback);
  StartClientRead();
  StartServerRead();
  StartControlRead();
  return ERR_IO_PENDING;
}

// --- Client → Server direction ---

void NaiveUdpConnection::StartClientRead() {
  if (client_done_) return;
  client_read_buf_ = base::MakeRefCounted<IOBufferWithSize>(kUdpBufSize);
  int rv = udp_relay_->RecvFrom(
      client_read_buf_.get(), kUdpBufSize, &client_addr_,
      base::BindOnce(&NaiveUdpConnection::OnClientReadComplete,
                     weak_ptr_factory_.GetWeakPtr()));
  if (rv != ERR_IO_PENDING) {
    OnClientReadComplete(rv);
  }
}

void NaiveUdpConnection::OnClientReadComplete(int result) {
  if (result <= 0) {
    client_done_ = true;
    MaybeComplete();
    return;
  }

  client_addr_known_ = true;

  // Parse SOCKS5 UDP header.
  HostPortPair dest;
  std::string_view payload;
  if (!ParseSocks5UdpPacket(
          reinterpret_cast<const uint8_t*>(client_read_buf_->data()),
          result, dest, payload)) {
    LOG(WARNING) << "UoT conn " << id_
                 << ": invalid SOCKS5 UDP packet, skipping";
    StartClientRead();
    return;
  }

  // First packet: send UoT handshake before the data. We use isConnect=false
  // so each data frame carries its own destination, matching SOCKS5 UDP
  // ASSOCIATE semantics (a single association may target many destinations).
  if (!handshake_sent_) {
    handshake_sent_ = true;
    pending_payload_ = std::string(payload);
    pending_payload_valid_ = true;
    pending_dest_ = dest;
    SendUotHandshake(dest);
    return;
  }

  // Subsequent packets: wrap in UoT data frame (with per-packet destination).
  std::string frame = NaiveUotFramer::EncodeDataTo(dest, payload);
  auto buf = base::MakeRefCounted<IOBufferWithSize>(frame.size());
  memcpy(buf->data(), frame.data(), frame.size());

  int rv = ServerWrite(
      buf.get(), buf->size(),
      base::BindOnce([](base::WeakPtr<NaiveUdpConnection> self, int rv) {
        if (self) self->StartClientRead();
      }, weak_ptr_factory_.GetWeakPtr()));
  last_write_time_ = base::TimeTicks::Now();
  if (rv != ERR_IO_PENDING) {
    if (rv < 0) {
      LOG(ERROR) << "UoT conn " << id_ << " server write error: " << rv;
      client_done_ = true;
      server_done_ = true;
      MaybeComplete();
      return;
    }
    StartClientRead();
  }
}

void NaiveUdpConnection::SendUotHandshake(const HostPortPair& dest) {
  // isConnect=false: the handshake destination is only a hint; real routing is
  // done per data frame. sing-box requires a valid destination here, so we pass
  // the first packet's destination.
  std::string handshake = NaiveUotFramer::EncodeHandshake(false, dest);
  auto buf = base::MakeRefCounted<IOBufferWithSize>(handshake.size());
  memcpy(buf->data(), handshake.data(), handshake.size());

  int rv = ServerWrite(
      buf.get(), buf->size(),
      base::BindOnce(&NaiveUdpConnection::OnHandshakeSent,
                     weak_ptr_factory_.GetWeakPtr()));
  last_write_time_ = base::TimeTicks::Now();
  if (rv != ERR_IO_PENDING) {
    OnHandshakeSent(rv);
  }
}

void NaiveUdpConnection::OnHandshakeSent(int result) {
  if (result < 0) {
    LOG(ERROR) << "UoT conn " << id_ << " handshake send failed: " << result;
    client_done_ = true;
    server_done_ = true;
    MaybeComplete();
    return;
  }

  // Now send the pending first-packet payload as a UoT data frame, carrying
  // its per-packet destination (isConnect=false mode). Note the payload may be
  // legitimately empty, so gate on the explicit validity flag, not emptiness.
  if (pending_payload_valid_) {
    std::string frame =
        NaiveUotFramer::EncodeDataTo(pending_dest_, pending_payload_);
    pending_payload_.clear();
    pending_payload_valid_ = false;
    auto buf = base::MakeRefCounted<IOBufferWithSize>(frame.size());
    memcpy(buf->data(), frame.data(), frame.size());

    int rv = ServerWrite(
        buf.get(), buf->size(),
        base::BindOnce([](base::WeakPtr<NaiveUdpConnection> self, int rv) {
          if (self) self->StartClientRead();
        }, weak_ptr_factory_.GetWeakPtr()));
    last_write_time_ = base::TimeTicks::Now();
    if (rv == ERR_IO_PENDING) {
      return;
    }
    if (rv < 0) {
      LOG(ERROR) << "UoT conn " << id_
                 << " first data frame send failed: " << rv;
      client_done_ = true;
      server_done_ = true;
      MaybeComplete();
      return;
    }
  }
  StartClientRead();
}

// --- Server → Client direction ---

void NaiveUdpConnection::StartServerRead() {
  if (server_done_) return;
  server_read_buf_ = base::MakeRefCounted<IOBufferWithSize>(kTcpBufSize);
  int rv = ServerRead(
      server_read_buf_.get(), kTcpBufSize,
      base::BindOnce(&NaiveUdpConnection::OnServerReadComplete,
                     weak_ptr_factory_.GetWeakPtr()));
  if (rv != ERR_IO_PENDING) {
    OnServerReadComplete(rv);
  }
}

void NaiveUdpConnection::OnServerReadComplete(int result) {
  if (result <= 0) {
    server_done_ = true;
    MaybeComplete();
    return;
  }

  // Feed bytes into UoT framer, processing all complete frames.
  const uint8_t* data =
      reinterpret_cast<const uint8_t*>(server_read_buf_->data());
  size_t pos = 0;
  while (pos < static_cast<size_t>(result)) {
    size_t consumed = 0;
    bool frame_complete =
        uot_framer_.Feed(data + pos, static_cast<size_t>(result) - pos,
                         &consumed);
    pos += consumed;
    if (!frame_complete) {
      if (uot_framer_.has_error()) {
        LOG(ERROR) << "UoT conn " << id_
                   << ": framer error, tearing down connection";
        server_done_ = true;
        client_done_ = true;
        MaybeComplete();
        return;
      }
      // Need more bytes. The framer has stored them internally.
      break;
    }
    if (uot_framer_.is_handshake()) {
      // Server sends a handshake (echoing destination). Skip it —
      // destination is already known from client's own handshake.
      continue;
    }
    // UoT data frame → wrap in SOCKS5 UDP header → send to client.
    if (!client_addr_known_) {
      // Client hasn't sent anything yet; we don't know where to send.
      // Drop the packet.
      LOG(WARNING) << "UoT conn " << id_
                   << ": server data before client addr known, dropping";
      continue;
    }
    std::string_view payload = uot_framer_.payload();
    std::string header = BuildSocks5UdpHeader(uot_framer_.destination());
    auto buf =
        base::MakeRefCounted<IOBufferWithSize>(header.size() + payload.size());
    memcpy(buf->data(), header.data(), header.size());
    memcpy(buf->data() + header.size(), payload.data(), payload.size());
    SendToClient(buf, buf->size());
  }

  StartServerRead();
}

void NaiveUdpConnection::SendToClient(scoped_refptr<IOBuffer> buf, int len) {
  if (!udp_relay_ || !client_addr_known_) return;
  int rv = udp_relay_->SendTo(
      buf.get(), len, client_addr_,
      base::BindOnce(&NaiveUdpConnection::OnSendToClientComplete,
                     weak_ptr_factory_.GetWeakPtr()));
  if (rv != ERR_IO_PENDING && rv < 0) {
    LOG(WARNING) << "UoT conn " << id_
                 << " send-to-client sync error: " << ErrorToShortString(rv);
  }
}

void NaiveUdpConnection::OnSendToClientComplete(int result) {
  if (result < 0) {
    LOG(WARNING) << "UoT conn " << id_ << " send-to-client error: " << result;
  }
}

// --- TCP control socket monitoring ---

void NaiveUdpConnection::StartControlRead() {
  if (control_done_ || !control_socket_) return;
  control_read_buf_ = base::MakeRefCounted<IOBufferWithSize>(kControlBufSize);
  int rv = control_socket_->Read(
      control_read_buf_.get(), kControlBufSize,
      base::BindOnce(&NaiveUdpConnection::OnControlReadComplete,
                     weak_ptr_factory_.GetWeakPtr()));
  if (rv != ERR_IO_PENDING) {
    OnControlReadComplete(rv);
  }
}

void NaiveUdpConnection::OnControlReadComplete(int result) {
  if (result <= 0) {
    // TCP control connection closed or errored → tear down UoT.
    LOG(INFO) << "UoT conn " << id_
              << " control socket closed: " << (result < 0 ? ErrorToShortString(result) : "EOF");
    control_done_ = true;
    client_done_ = true;
    server_done_ = true;
    MaybeComplete();
    return;
  }
  // Control connection has data — this is unexpected for UDP ASSOCIATE
  // (control connection should stay idle). Just read and discard.
  StartControlRead();
}

void NaiveUdpConnection::MaybeComplete() {
  if ((client_done_ && server_done_) || control_done_) {
    if (udp_relay_) udp_relay_->Close();
    if (control_socket_) control_socket_->Disconnect();
    if (server_socket_handle_ && server_socket_handle_->socket())
      server_socket_handle_->socket()->Disconnect();
    if (run_callback_) {
      std::move(run_callback_).Run(OK);
    }
  }
}

std::optional<PaddingType>
NaiveUdpConnection::GetServerPaddingType() const {
  auto* proxy_delegate =
      static_cast<NaiveProxyDelegate*>(session_->context().proxy_delegate);
  if (!proxy_delegate) return std::nullopt;
  return proxy_delegate->GetProxyChainPaddingType(proxy_info_.proxy_chain());
}

int NaiveUdpConnection::ServerWrite(IOBuffer* buf, int buf_len,
                                     CompletionOnceCallback callback) {
  if (server_padding_socket_) {
    return server_padding_socket_->Write(buf, buf_len, std::move(callback),
                                         traffic_annotation_);
  }
  return server_socket_handle_->socket()->Write(
      buf, buf_len, std::move(callback), traffic_annotation_);
}

int NaiveUdpConnection::ServerRead(IOBuffer* buf, int buf_len,
                                    CompletionOnceCallback callback) {
  if (server_padding_socket_) {
    return server_padding_socket_->Read(buf, buf_len, std::move(callback));
  }
  return server_socket_handle_->socket()->Read(buf, buf_len,
                                               std::move(callback));
}

}  // namespace net
