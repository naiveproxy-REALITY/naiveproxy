// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_HTTP_REALITY_FALLBACK_H_
#define NET_HTTP_REALITY_FALLBACK_H_

#include <memory>
#include <string>

#include "base/functional/callback.h"
#include "base/memory/scoped_refptr.h"
#include "base/memory/weak_ptr.h"
#include "base/timer/timer.h"
#include "net/base/io_buffer.h"
#include "net/base/load_timing_info.h"
#include "net/http/http_request_info.h"
#include "net/http/http_response_info.h"
#include "net/log/net_log_with_source.h"

namespace net {

class HostPortPair;
class HttpStream;
class SpdySessionPool;
class SSLClientSocket;

// A single GET to the authenticated camouflage site, on the exact TLS socket
// that failed REALITY authentication. Owned by HttpNetworkSession, independently
// of the failed application request. Its private pool is never visible to other
// transactions, even when network state partitioning is disabled.
class RealityFallback {
 public:
  RealityFallback(std::unique_ptr<SpdySessionPool> spdy_pool,
                  base::OnceCallback<void(RealityFallback*)> done);
  ~RealityFallback();

  void Start(std::unique_ptr<SSLClientSocket> socket,
             const HostPortPair& host_and_port,
             const LoadTimingInfo::ConnectTiming& connect_timing,
             const std::string& user_agent);

 private:
  enum class State {
    kInitialize,
    kSend,
    kReadHeaders,
    kReadHeadersComplete,
    kReadBody,
    kReadBodyComplete,
  };

  void OnIOComplete(int result);
  void Finish();
  void NotifyDone();

  base::OnceCallback<void(RealityFallback*)> done_;
  std::unique_ptr<SpdySessionPool> spdy_pool_;
  HttpRequestInfo request_;
  HttpResponseInfo response_;
  NetLogWithSource net_log_;
  scoped_refptr<IOBufferWithSize> read_buffer_;
  std::unique_ptr<HttpStream> stream_;
  State state_ = State::kInitialize;
  bool finished_ = false;
  base::OneShotTimer timer_;
  base::WeakPtrFactory<RealityFallback> weak_factory_{this};
};

}  // namespace net

#endif  // NET_HTTP_REALITY_FALLBACK_H_
