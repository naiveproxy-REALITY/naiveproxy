// Copyright 2024 NaiveProxy-REALITY contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#ifndef NET_TOOLS_NAIVE_NAIVE_UOT_FRAMER_H_
#define NET_TOOLS_NAIVE_NAIVE_UOT_FRAMER_H_

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "net/base/host_port_pair.h"
#include "net/base/ip_address.h"

namespace net {

// Magic address for UoT v2 (sing-box compatible).
inline constexpr const char* kUotMagicAddress = "sp.v2.udp-over-tcp.arpa";
inline constexpr const char* kUotLegacyMagicAddress = "sp.udp-over-tcp.arpa";

// UoT v2 wire format (sing-box compatible).
//
//   Handshake (first frame, sent once):
//     [1 byte: isConnect]
//     [1 byte: addr_type] [addr_data] [2 bytes BE: port]
//   Handshake address encoding uses sing-box M.SocksaddrSerializer:
//     0x01: IPv4  — 4 bytes IP
//     0x04: IPv6  — 16 bytes IP
//     0x03: FQDN  — 1 byte len + N bytes domain
//   ...followed by [2 bytes BE: port].
//
//   Data frames after handshake:
//     isConnect=true  (fixed destination):
//       [2 bytes BE: payload_length] [payload]
//     isConnect=false (per-packet destination):
//       [1 byte: addr_type] [addr_data] [2 bytes BE: port]
//       [2 bytes BE: payload_length] [payload]
//   Per-packet address encoding uses sing-box uot.AddrParser (DIFFERENT bytes
//   from the handshake serializer):
//     0x00: IPv4  — 4 bytes IP
//     0x01: IPv6  — 16 bytes IP
//     0x02: FQDN  — 1 byte len + N bytes domain
//   ...followed by [2 bytes BE: port].
class NaiveUotFramer {
 public:
  // Which address-type byte mapping to use when (de)serializing an address.
  enum class AddrScheme {
    kSocks5,  // Handshake: IPv4=0x01, IPv6=0x04, FQDN=0x03.
    kUot,     // Per-packet: IPv4=0x00, IPv6=0x01, FQDN=0x02.
  };

  NaiveUotFramer();
  ~NaiveUotFramer();

  // ---- Encode side ----

  // Builds the UoT v2 handshake frame.
  // isConnect=true means the destination is fixed for the entire connection;
  // isConnect=false means each data frame carries its own destination.
  static std::string EncodeHandshake(bool is_connect,
                                     const HostPortPair& destination);

  // Encodes a single UoT data frame for isConnect=true mode.
  // Returns [2 bytes BE length][payload].
  static std::string EncodeData(std::string_view payload);

  // Encodes a single UoT data frame for isConnect=false mode.
  // Returns [uot addr][2 bytes BE port][2 bytes BE length][payload].
  static std::string EncodeDataTo(const HostPortPair& destination,
                                  std::string_view payload);

  // ---- Decode side ----

  enum class ReadState {
    kHandshakeIsConnect,
    kHandshakeAddrType,
    kHandshakeIPv4,
    kHandshakeIPv6,
    kHandshakeDomainLen,
    kHandshakeDomain,
    kHandshakePort,
    // isConnect=false per-packet address (uot.AddrParser scheme).
    kDataAddrType,
    kDataIPv4,
    kDataIPv6,
    kDataDomainLen,
    kDataDomain,
    kDataPort,
    // Payload length + payload (both modes).
    kDataLength1,
    kDataLength2,
    kData,
  };

  // Feeds bytes into the decoder. Returns true if a complete frame has been
  // decoded. *bytes_consumed is set to the number of bytes consumed from the
  // input buffer. When a frame is complete, bytes_consumed may be less than
  // len (the remaining bytes belong to the next frame and must be fed again).
  // When no frame is complete, bytes_consumed equals len (all bytes stored
  // internally).
  // Call payload() and destination() to retrieve the result.
  bool Feed(const uint8_t* data, size_t len, size_t* bytes_consumed);

  // Initialize this framer as a DATAGRAM reader for the return (server->client)
  // direction, i.e. one that does NOT expect a leading handshake frame.
  //
  // Standard sing-box UoT servers do not echo a handshake; after they read the
  // client's request they send data frames directly. (Our earlier server sent a
  // handshake echo, which was a non-standard deviation; both sides now follow
  // the plain sing-box wire.) A return-direction framer must therefore start in
  // the data-frame state: for isConnect=false each frame carries its own
  // uot.AddrParser-encoded destination; for isConnect=true frames are bare
  // length+payload with the destination fixed to the association target.
  void InitAsDatagramReader(bool is_connect) {
    is_connect_ = is_connect;
    is_handshake_ = false;
    handshake_done_ = true;
    frame_addr_parsed_ = false;
    SetReadState(ReadState::kDataLength1);
  }

  // After Feed() returns true:
  // - For handshake: destination() is the parsed handshake destination.
  // - For data: payload() is the UDP packet data, and destination() is the
  //   per-packet destination (isConnect=false) or the handshake destination
  //   (isConnect=true).
  bool is_handshake() const { return is_handshake_; }
  bool is_connect() const { return is_connect_; }
  const HostPortPair& destination() const { return destination_; }
  std::string_view payload() const { return payload_; }

  // Whether the handshake has been parsed.
  bool handshake_done() const { return handshake_done_; }

  // Whether the framer encountered a fatal error (e.g. invalid address type).
  // Once in error state, Feed() returns false with *consumed=0 for all calls.
  bool has_error() const { return has_error_; }

 private:
  // Appends [addr_type][addr_data][port BE 2] to `out` using `scheme`.
  static void AppendAddress(std::string* out,
                            AddrScheme scheme,
                            const HostPortPair& dest);

  void SetReadState(ReadState state);

  ReadState state_ = ReadState::kHandshakeIsConnect;
  bool handshake_done_ = false;
  bool has_error_ = false;
  bool is_handshake_ = false;
  bool is_connect_ = false;
  HostPortPair destination_;

  // Reusable buffer for accumulating multi-byte fields.
  std::string accumulator_;
  size_t needed_ = 0;

  // Decoded payload for data frames.
  std::string payload_;
  uint16_t data_length_ = 0;

  // isConnect=false only: whether the per-packet address for the in-progress
  // data frame has already been parsed (so kDataLength1 knows to skip it).
  bool frame_addr_parsed_ = false;
};

}  // namespace net
#endif  // NET_TOOLS_NAIVE_NAIVE_UOT_FRAMER_H_
