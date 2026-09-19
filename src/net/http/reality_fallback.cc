// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/reality_fallback.h"

#include <set>
#include <utility>

#include "base/functional/bind.h"
#include "base/rand_util.h"
#include "base/task/sequenced_task_runner.h"
#include "net/base/host_port_pair.h"
#include "net/base/net_errors.h"
#include "net/http/http_basic_stream.h"
#include "net/http/http_response_headers.h"
#include "net/http/http_stream.h"
#include "net/socket/client_socket_handle.h"
#include "net/socket/ssl_client_socket.h"
#include "net/spdy/spdy_http_stream.h"
#include "net/spdy/spdy_session_pool.h"
#include "net/traffic_annotation/network_traffic_annotation.h"

namespace net {

RealityFallback::RealityFallback(
    std::unique_ptr<SpdySessionPool> spdy_pool,
    base::OnceCallback<void(RealityFallback*)> done)
    : done_(std::move(done)), spdy_pool_(std::move(spdy_pool)) {}

RealityFallback::~RealityFallback() {
  // Destroy the HTTP stream before its request/response storage and pool.
  if (stream_) {
    stream_->Close(/*not_reusable=*/true);
    stream_.reset();
  }
}

void RealityFallback::Start(
    std::unique_ptr<SSLClientSocket> socket,
    const HostPortPair& host_and_port,
    const LoadTimingInfo::ConnectTiming& connect_timing,
    const std::string& user_agent) {
  net_log_ = socket->NetLog();
  // The URL uses the verified SNI, not the XHTTP Host, path, query or endpoint
  // port. No application headers, cookies, credentials or upload are copied.
  request_.url = GURL("https://" + host_and_port.HostForURL() + "/");
  request_.method = "GET";
  request_.extra_headers.SetHeader("Host", host_and_port.HostForURL());
  request_.extra_headers.SetHeader("User-Agent", user_agent);
  request_.extra_headers.SetHeader("Accept", "*/*");
  request_.extra_headers.SetHeader("Accept-Encoding", "gzip, deflate, br, zstd");
  request_.extra_headers.SetHeader(
      "Cookie", "padding=" + std::string(base::RandIntInclusive(30, 61), '0'));
  request_.traffic_annotation = MutableNetworkTrafficAnnotationTag(
      DefineNetworkTrafficAnnotation("reality_camouflage", R"(
        semantics {
          sender: "REALITY client"
          description: "Visits the authenticated camouflage site when REALITY authentication fails."
          trigger: "A REALITY connection presents a valid ordinary website certificate."
          data: "A GET for the site root, user agent, and a random padding cookie."
          destination: WEBSITE
        }
        policy {
          cookies_allowed: NO
          setting: "Only enabled for an explicitly configured REALITY client."
          policy_exception_justification: "Not used in Chrome."
        })"));

  if (socket->GetNegotiatedProtocol() == NextProto::kProtoHTTP2) {
    CHECK(spdy_pool_);
    SpdySessionKey key(HostPortPair::FromURL(request_.url),
                       PRIVACY_MODE_DISABLED, ProxyChain::Direct(),
                       SessionUsage::kDestination, SocketTag(),
                       NetworkAnonymizationKey::CreateTransient(),
                       SecureDnsPolicy::kDisable,
                       /*disable_cert_verification_network_fetches=*/true,
                       handles::kInvalidNetworkHandle);
    auto result = spdy_pool_->CreateAvailableSessionFromSocket(
        key, std::move(socket), connect_timing, net_log_);
    if (!result.has_value()) {
      Finish();
      return;
    }
    stream_ = std::make_unique<SpdyHttpStream>(
        result.value(), net_log_.source(), std::set<std::string>());
  } else {
    // An ordinary site without ALPN uses HTTP/1.1. REALITY's prior-knowledge
    // h2 compatibility is restricted to REALITY-authenticated sockets.
    auto handle = std::make_unique<ClientSocketHandle>();
    handle->SetSocket(std::move(socket));
    handle->set_connect_timing(connect_timing);
    stream_ = std::make_unique<HttpBasicStream>(std::move(handle), false);
  }

  read_buffer_ = base::MakeRefCounted<IOBufferWithSize>(32 * 1024);
  stream_->RegisterRequest(&request_);
  timer_.Start(FROM_HERE, base::Seconds(30), this, &RealityFallback::Finish);
  OnIOComplete(OK);
}

void RealityFallback::OnIOComplete(int result) {
  // Yield while draining a large buffered response so the network thread can
  // process cancellation, other connections, and the timeout.
  for (int steps = 0; steps < 32; ++steps) {
    if (result < 0) {
      Finish();
      return;
    }
    auto callback = base::BindOnce(&RealityFallback::OnIOComplete,
                                   weak_factory_.GetWeakPtr());
    switch (state_) {
      case State::kInitialize:
        state_ = State::kSend;
        result = stream_->InitializeStream(false, DEFAULT_PRIORITY, net_log_,
                                           std::move(callback));
        break;
      case State::kSend:
        state_ = State::kReadHeaders;
        result = stream_->SendRequest(request_.extra_headers, &response_,
                                      std::move(callback));
        break;
      case State::kReadHeaders:
        state_ = State::kReadHeadersComplete;
        result = stream_->ReadResponseHeaders(std::move(callback));
        break;
      case State::kReadHeadersComplete:
        if (response_.headers->response_code() < 200) {
          // HTTP/1.1 can surface informational headers separately.
          state_ = State::kReadHeaders;
        } else {
          state_ = State::kReadBody;
        }
        break;
      case State::kReadBody:
        state_ = State::kReadBodyComplete;
        result = stream_->ReadResponseBody(
            read_buffer_.get(), read_buffer_->size(), std::move(callback));
        break;
      case State::kReadBodyComplete:
        if (result == 0) {
          Finish();
          return;
        }
        state_ = State::kReadBody;
        break;
    }
    if (result == ERR_IO_PENDING) {
      return;
    }
  }
  base::SequencedTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE, base::BindOnce(&RealityFallback::OnIOComplete,
                               weak_factory_.GetWeakPtr(), result));
}

void RealityFallback::Finish() {
  if (finished_) {
    return;
  }
  finished_ = true;
  timer_.Stop();
  weak_factory_.InvalidateWeakPtrs();
  // Never destroy an HTTP stream from within its own completion callback.
  base::SequencedTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE, base::BindOnce(&RealityFallback::NotifyDone,
                               weak_factory_.GetWeakPtr()));
}

void RealityFallback::NotifyDone() {
  std::move(done_).Run(this);
}

}  // namespace net
