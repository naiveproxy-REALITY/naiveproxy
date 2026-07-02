// Copyright 2024 NaiveProxy-REALITY contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include "net/tools/naive/naive_uot_framer.h"

#include <algorithm>
#include <array>
#include <cstring>

#include "base/containers/span.h"
#include "base/numerics/byte_conversions.h"
#include "net/base/ip_endpoint.h"

namespace net {

namespace {

// Handshake address-type bytes (sing-box M.SocksaddrSerializer).
constexpr uint8_t kSocks5IPv4 = 0x01;
constexpr uint8_t kSocks5IPv6 = 0x04;
constexpr uint8_t kSocks5Domain = 0x03;

// Per-packet address-type bytes (sing-box uot.AddrParser). These deliberately
// differ from the handshake serializer above.
constexpr uint8_t kUotIPv4 = 0x00;
constexpr uint8_t kUotIPv6 = 0x01;
constexpr uint8_t kUotDomain = 0x02;

// Normalizes an IPv4-mapped-IPv6 address (::ffff:a.b.c.d) down to IPv4, to
// match sing-box's Socksaddr.Unwrap() behavior.
IPAddress UnwrapIfV4Mapped(const IPAddress& ip) {
  if (ip.IsIPv4MappedIPv6()) {
    return ConvertIPv4MappedIPv6ToIPv4(ip);
  }
  return ip;
}

}  // namespace

NaiveUotFramer::NaiveUotFramer() = default;
NaiveUotFramer::~NaiveUotFramer() = default;

// static
void NaiveUotFramer::AppendAddress(std::string* out,
                                   AddrScheme scheme,
                                   const HostPortPair& dest) {
  const uint8_t v4 = scheme == AddrScheme::kSocks5 ? kSocks5IPv4 : kUotIPv4;
  const uint8_t v6 = scheme == AddrScheme::kSocks5 ? kSocks5IPv6 : kUotIPv6;
  const uint8_t fqdn =
      scheme == AddrScheme::kSocks5 ? kSocks5Domain : kUotDomain;

  IPAddress ip;
  bool is_ip = ip.AssignFromIPLiteral(dest.host());
  if (is_ip) {
    ip = UnwrapIfV4Mapped(ip);
  }
  if (is_ip && ip.IsIPv4()) {
    out->push_back(static_cast<char>(v4));
    const auto bytes = ip.bytes();
    out->append(reinterpret_cast<const char*>(bytes.data()), 4);
  } else if (is_ip && ip.IsIPv6()) {
    out->push_back(static_cast<char>(v6));
    const auto bytes = ip.bytes();
    out->append(reinterpret_cast<const char*>(bytes.data()), 16);
  } else {
    // Domain. sing-box WriteSocksString errors on len > 255; clamp defensively.
    std::string host = dest.host();
    if (host.size() > 255) {
      host.resize(255);
    }
    out->push_back(static_cast<char>(fqdn));
    out->push_back(static_cast<char>(static_cast<uint8_t>(host.size())));
    out->append(host);
  }

  // Port (big-endian), appended after the address in both serializers.
  const std::array<uint8_t, 2u> port_be = base::U16ToBigEndian(dest.port());
  out->append(reinterpret_cast<const char*>(port_be.data()), 2);
}

// static
std::string NaiveUotFramer::EncodeHandshake(bool is_connect,
                                            const HostPortPair& dest) {
  std::string out;
  out.push_back(is_connect ? 0x01 : 0x00);
  AppendAddress(&out, AddrScheme::kSocks5, dest);
  return out;
}

// static
std::string NaiveUotFramer::EncodeData(std::string_view payload) {
  std::string out;
  const std::array<uint8_t, 2u> len_be =
      base::U16ToBigEndian(static_cast<uint16_t>(payload.size()));
  out.append(reinterpret_cast<const char*>(len_be.data()), 2);
  out.append(payload);
  return out;
}

// static
std::string NaiveUotFramer::EncodeDataTo(const HostPortPair& dest,
                                         std::string_view payload) {
  std::string out;
  AppendAddress(&out, AddrScheme::kUot, dest);
  const std::array<uint8_t, 2u> len_be =
      base::U16ToBigEndian(static_cast<uint16_t>(payload.size()));
  out.append(reinterpret_cast<const char*>(len_be.data()), 2);
  out.append(payload);
  return out;
}

void NaiveUotFramer::SetReadState(ReadState state) {
  state_ = state;
  accumulator_.clear();
  needed_ = 0;
}

bool NaiveUotFramer::Feed(const uint8_t* data, size_t len, size_t* consumed) {
  if (has_error_) {
    if (consumed) *consumed = 0;
    return false;
  }
  size_t pos = 0;
  while (pos < len) {
    size_t remaining = len - pos;
    size_t to_copy;

    switch (state_) {
      case ReadState::kHandshakeIsConnect:
        is_handshake_ = true;
        is_connect_ = (data[pos] != 0);
        pos++;
        SetReadState(ReadState::kHandshakeAddrType);
        break;

      case ReadState::kHandshakeAddrType: {
        uint8_t addr_type = data[pos];
        pos++;
        if (addr_type == kSocks5IPv4) {
          SetReadState(ReadState::kHandshakeIPv4);
          needed_ = 4;
        } else if (addr_type == kSocks5IPv6) {
          SetReadState(ReadState::kHandshakeIPv6);
          needed_ = 16;
        } else if (addr_type == kSocks5Domain) {
          SetReadState(ReadState::kHandshakeDomainLen);
        } else {
          has_error_ = true;
          if (consumed) *consumed = pos;
          return false;
        }
        break;
      }

      case ReadState::kHandshakeIPv4:
      case ReadState::kHandshakeIPv6:
      case ReadState::kDataIPv4:
      case ReadState::kDataIPv6: {
        to_copy = std::min(needed_ - accumulator_.size(), remaining);
        accumulator_.append(reinterpret_cast<const char*>(data + pos), to_copy);
        pos += to_copy;
        if (accumulator_.size() == needed_) {
          IPAddress ip(base::as_byte_span(accumulator_));
          ip = UnwrapIfV4Mapped(ip);
          IPEndPoint ep(ip, 0);
          destination_ = HostPortPair::FromIPEndPoint(ep);
          bool is_handshake_addr = state_ == ReadState::kHandshakeIPv4 ||
                                   state_ == ReadState::kHandshakeIPv6;
          SetReadState(is_handshake_addr ? ReadState::kHandshakePort
                                         : ReadState::kDataPort);
        }
        break;
      }

      case ReadState::kHandshakeDomainLen:
      case ReadState::kDataDomainLen: {
        uint8_t domain_len = data[pos];
        pos++;
        if (domain_len == 0) {
          // Empty host is invalid.
          has_error_ = true;
          if (consumed) *consumed = pos;
          return false;
        }
        bool is_handshake_addr = state_ == ReadState::kHandshakeDomainLen;
        SetReadState(is_handshake_addr ? ReadState::kHandshakeDomain
                                       : ReadState::kDataDomain);
        needed_ = domain_len;
        break;
      }

      case ReadState::kHandshakeDomain:
      case ReadState::kDataDomain: {
        to_copy = std::min(needed_ - accumulator_.size(), remaining);
        accumulator_.append(reinterpret_cast<const char*>(data + pos), to_copy);
        pos += to_copy;
        if (accumulator_.size() == needed_) {
          destination_ = HostPortPair(accumulator_, 0);  // port set next.
          bool is_handshake_addr = state_ == ReadState::kHandshakeDomain;
          SetReadState(is_handshake_addr ? ReadState::kHandshakePort
                                         : ReadState::kDataPort);
        }
        break;
      }

      case ReadState::kHandshakePort:
      case ReadState::kDataPort: {
        to_copy = std::min(size_t{2} - accumulator_.size(), remaining);
        accumulator_.append(reinterpret_cast<const char*>(data + pos), to_copy);
        pos += to_copy;
        if (accumulator_.size() == 2) {
          const uint8_t port_bytes[2] = {
              static_cast<uint8_t>(accumulator_[0]),
              static_cast<uint8_t>(accumulator_[1])};
          uint16_t port = base::U16FromBigEndian(port_bytes);
          destination_ = HostPortPair(destination_.host(), port);
          bool is_handshake_addr = state_ == ReadState::kHandshakePort;
          if (is_handshake_addr) {
            handshake_done_ = true;
            SetReadState(ReadState::kDataLength1);
            // Handshake frame complete.
            if (consumed) *consumed = pos;
            return true;
          }
          // isConnect=false per-packet address parsed; continue to length.
          frame_addr_parsed_ = true;
          SetReadState(ReadState::kDataLength1);
        }
        break;
      }

      case ReadState::kDataAddrType: {
        // Only reached in isConnect=false mode.
        uint8_t addr_type = data[pos];
        pos++;
        if (addr_type == kUotIPv4) {
          SetReadState(ReadState::kDataIPv4);
          needed_ = 4;
        } else if (addr_type == kUotIPv6) {
          SetReadState(ReadState::kDataIPv6);
          needed_ = 16;
        } else if (addr_type == kUotDomain) {
          SetReadState(ReadState::kDataDomainLen);
        } else {
          has_error_ = true;
          if (consumed) *consumed = pos;
          return false;
        }
        break;
      }

      case ReadState::kDataLength1:
        is_handshake_ = false;
        // In isConnect=false mode, a per-packet address precedes the length.
        // Detect the start of a fresh data frame: if we have not yet consumed
        // the per-packet address for this frame, redirect to kDataAddrType.
        if (!is_connect_ && !frame_addr_parsed_) {
          SetReadState(ReadState::kDataAddrType);
          break;
        }
        data_length_ = static_cast<uint16_t>(data[pos]) << 8;
        pos++;
        SetReadState(ReadState::kDataLength2);
        break;

      case ReadState::kDataLength2:
        is_handshake_ = false;
        data_length_ |= data[pos];
        pos++;
        if (data_length_ == 0) {
          payload_.clear();
          frame_addr_parsed_ = false;
          SetReadState(ReadState::kDataLength1);
          if (consumed) *consumed = pos;
          return true;
        }
        payload_.clear();
        SetReadState(ReadState::kData);
        break;

      case ReadState::kData:
        to_copy = std::min(static_cast<size_t>(data_length_) - payload_.size(),
                           remaining);
        payload_.append(reinterpret_cast<const char*>(data + pos), to_copy);
        pos += to_copy;
        if (payload_.size() == data_length_) {
          frame_addr_parsed_ = false;
          SetReadState(ReadState::kDataLength1);
          if (consumed) *consumed = pos;
          return true;
        }
        break;
    }
  }
  if (consumed) *consumed = pos;
  return false;
}

}  // namespace net
