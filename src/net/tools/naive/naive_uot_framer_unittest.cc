// Copyright 2024 NaiveProxy-REALITY contributors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/tools/naive/naive_uot_framer.h"
#include "net/tools/naive/naive_udp_connection.h"

#include <string>
#include <string_view>
#include <vector>

#include "base/sys_byteorder.h"
#include "net/base/host_port_pair.h"
#include "net/base/ip_address.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

// Helper to convert string to uint8_t span.
const uint8_t* AsBytes(const std::string& s) {
  return reinterpret_cast<const uint8_t*>(s.data());
}

}  // namespace

// ==========================================================================
// NaiveUotFramer: Encode tests
// ==========================================================================

TEST(NaiveUotFramerTest, EncodeHandshakeIPv4) {
  HostPortPair dest("1.2.3.4", 5678);
  std::string frame = NaiveUotFramer::EncodeHandshake(true, dest);

  EXPECT_EQ(frame.size(), 8u);  // 1 + 1 + 4 + 2
  EXPECT_EQ(static_cast<uint8_t>(frame[0]), 0x01);  // isConnect
  EXPECT_EQ(static_cast<uint8_t>(frame[1]), 0x01);  // IPv4
  EXPECT_EQ(static_cast<uint8_t>(frame[6]), 0x16);  // port high
  EXPECT_EQ(static_cast<uint8_t>(frame[7]), 0x2E);  // port low
}

TEST(NaiveUotFramerTest, EncodeHandshakeIPv6) {
  HostPortPair dest("2001:db8::1", 443);
  std::string frame = NaiveUotFramer::EncodeHandshake(true, dest);

  EXPECT_EQ(frame.size(), 20u);  // 1 + 1 + 16 + 2
  EXPECT_EQ(static_cast<uint8_t>(frame[0]), 0x01);
  EXPECT_EQ(static_cast<uint8_t>(frame[1]), 0x04);  // IPv6
}

TEST(NaiveUotFramerTest, EncodeHandshakeDomain) {
  HostPortPair dest("example.com", 80);
  std::string frame = NaiveUotFramer::EncodeHandshake(true, dest);

  EXPECT_EQ(frame.size(), 16u);  // 1 + 1 + 1 + 11 + 2
  EXPECT_EQ(static_cast<uint8_t>(frame[0]), 0x01);
  EXPECT_EQ(static_cast<uint8_t>(frame[1]), 0x03);  // Domain
  EXPECT_EQ(static_cast<uint8_t>(frame[2]), 11);
  EXPECT_EQ(frame.substr(3, 11), "example.com");
}

TEST(NaiveUotFramerTest, EncodeHandshakeIsConnectFalse) {
  HostPortPair dest("1.2.3.4", 53);
  std::string frame = NaiveUotFramer::EncodeHandshake(false, dest);
  EXPECT_EQ(static_cast<uint8_t>(frame[0]), 0x00);
}

TEST(NaiveUotFramerTest, EncodeDataSimple) {
  std::string frame = NaiveUotFramer::EncodeData("hello");
  EXPECT_EQ(frame.size(), 7u);  // 2 + 5
  EXPECT_EQ(static_cast<uint8_t>(frame[0]), 0x00);
  EXPECT_EQ(static_cast<uint8_t>(frame[1]), 0x05);
  EXPECT_EQ(frame.substr(2), "hello");
}

TEST(NaiveUotFramerTest, EncodeDataEmpty) {
  std::string frame = NaiveUotFramer::EncodeData("");
  EXPECT_EQ(frame.size(), 2u);
}

TEST(NaiveUotFramerTest, EncodeDataMaxLength) {
  std::string payload(65535, 'X');
  std::string frame = NaiveUotFramer::EncodeData(payload);
  EXPECT_EQ(frame.size(), 65537u);
  EXPECT_EQ(static_cast<uint8_t>(frame[0]), 0xFF);
  EXPECT_EQ(static_cast<uint8_t>(frame[1]), 0xFF);
}

// ==========================================================================
// NaiveUotFramer: Feed (decode) tests
// ==========================================================================

TEST(NaiveUotFramerTest, FeedHandshakeIPv4AllAtOnce) {
  HostPortPair dest("1.2.3.4", 5678);
  std::string frame = NaiveUotFramer::EncodeHandshake(true, dest);

  NaiveUotFramer framer;
  size_t consumed = 0;
  bool ok = framer.Feed(AsBytes(frame), frame.size(), &consumed);

  EXPECT_TRUE(ok);
  EXPECT_EQ(consumed, frame.size());
  EXPECT_TRUE(framer.is_handshake());
  EXPECT_TRUE(framer.is_connect());
  EXPECT_TRUE(framer.handshake_done());
  EXPECT_EQ(framer.destination().host(), "1.2.3.4");
  EXPECT_EQ(framer.destination().port(), 5678);
}

TEST(NaiveUotFramerTest, FeedHandshakeIPv6AllAtOnce) {
  HostPortPair dest("2001:db8::1", 443);
  std::string frame = NaiveUotFramer::EncodeHandshake(true, dest);

  NaiveUotFramer framer;
  size_t consumed = 0;
  bool ok = framer.Feed(AsBytes(frame), frame.size(), &consumed);

  EXPECT_TRUE(ok);
  EXPECT_EQ(consumed, frame.size());
  EXPECT_TRUE(framer.handshake_done());
  EXPECT_EQ(framer.destination().port(), 443);
}

TEST(NaiveUotFramerTest, FeedHandshakeDomainAllAtOnce) {
  HostPortPair dest("example.com", 80);
  std::string frame = NaiveUotFramer::EncodeHandshake(true, dest);

  NaiveUotFramer framer;
  size_t consumed = 0;
  bool ok = framer.Feed(AsBytes(frame), frame.size(), &consumed);

  EXPECT_TRUE(ok);
  EXPECT_EQ(framer.destination().host(), "example.com");
  EXPECT_EQ(framer.destination().port(), 80);
}

TEST(NaiveUotFramerTest, FeedHandshakeByteByByte) {
  HostPortPair dest("1.2.3.4", 9999);
  std::string frame = NaiveUotFramer::EncodeHandshake(true, dest);

  NaiveUotFramer framer;
  bool got_frame = false;
  for (size_t i = 0; i < frame.size(); i++) {
    size_t consumed = 0;
    if (framer.Feed(AsBytes(frame) + i, 1, &consumed)) {
      got_frame = true;
      EXPECT_EQ(consumed, 1u);
      break;
    }
    EXPECT_EQ(consumed, 1u);
  }
  EXPECT_TRUE(got_frame);
  EXPECT_EQ(framer.destination().port(), 9999);
}

TEST(NaiveUotFramerTest, FeedHandshakeSplitAtEveryBoundary) {
  HostPortPair dest("example.com", 443);
  std::string frame = NaiveUotFramer::EncodeHandshake(true, dest);

  for (size_t split = 1; split < frame.size(); split++) {
    NaiveUotFramer framer;
    size_t c1 = 0, c2 = 0;
    framer.Feed(AsBytes(frame), split, &c1);
    bool ok = framer.Feed(AsBytes(frame) + c1, frame.size() - c1, &c2);
    EXPECT_TRUE(ok) << "split=" << split;
    EXPECT_EQ(c1 + c2, frame.size()) << "split=" << split;
    EXPECT_EQ(framer.destination().host(), "example.com") << "split=" << split;
    EXPECT_EQ(framer.destination().port(), 443) << "split=" << split;
  }
}

TEST(NaiveUotFramerTest, FeedHandshakeInvalidAddrType) {
  uint8_t data[] = {0x01, 0x05};
  NaiveUotFramer framer;
  size_t consumed = 0;
  EXPECT_FALSE(framer.Feed(data, 2, &consumed));
}

TEST(NaiveUotFramerTest, FeedDataFrameSimple) {
  HostPortPair dest("1.2.3.4", 53);
  std::string hs = NaiveUotFramer::EncodeHandshake(true, dest);
  NaiveUotFramer framer;
  size_t consumed = 0;
  framer.Feed(AsBytes(hs), hs.size(), &consumed);

  std::string payload = "DNS query";
  std::string frame = NaiveUotFramer::EncodeData(payload);
  consumed = 0;
  bool ok = framer.Feed(AsBytes(frame), frame.size(), &consumed);

  EXPECT_TRUE(ok);
  EXPECT_EQ(consumed, frame.size());
  EXPECT_FALSE(framer.is_handshake());
  EXPECT_EQ(std::string(framer.payload()), payload);
}

TEST(NaiveUotFramerTest, FeedDataFrameEmpty) {
  HostPortPair dest("1.2.3.4", 53);
  std::string hs = NaiveUotFramer::EncodeHandshake(true, dest);
  NaiveUotFramer framer;
  size_t consumed = 0;
  framer.Feed(AsBytes(hs), hs.size(), &consumed);

  std::string frame = NaiveUotFramer::EncodeData("");
  consumed = 0;
  bool ok = framer.Feed(AsBytes(frame), frame.size(), &consumed);

  EXPECT_TRUE(ok);
  EXPECT_EQ(framer.payload().size(), 0u);
}

TEST(NaiveUotFramerTest, FeedMultipleDataFramesInOneBuffer) {
  HostPortPair dest("1.2.3.4", 53);
  std::string hs = NaiveUotFramer::EncodeHandshake(true, dest);
  NaiveUotFramer framer;
  size_t consumed = 0;
  framer.Feed(AsBytes(hs), hs.size(), &consumed);

  std::string combined = NaiveUotFramer::EncodeData("first") +
                          NaiveUotFramer::EncodeData("second") +
                          NaiveUotFramer::EncodeData("third");

  const uint8_t* data = AsBytes(combined);
  size_t pos = 0;
  std::vector<std::string> results;
  while (pos < combined.size()) {
    consumed = 0;
    bool ok = framer.Feed(data + pos, combined.size() - pos, &consumed);
    pos += consumed;
    if (ok) {
      results.push_back(std::string(framer.payload()));
    } else {
      break;
    }
  }

  EXPECT_EQ(results.size(), 3u);
  EXPECT_EQ(results[0], "first");
  EXPECT_EQ(results[1], "second");
  EXPECT_EQ(results[2], "third");
  EXPECT_EQ(pos, combined.size());
}

TEST(NaiveUotFramerTest, FeedHandshakeAndDataInOneBuffer) {
  HostPortPair dest("8.8.8.8", 53);
  std::string hs = NaiveUotFramer::EncodeHandshake(true, dest);
  std::string payload = "DNS query";
  std::string df = NaiveUotFramer::EncodeData(payload);
  std::string combined = hs + df;

  NaiveUotFramer framer;
  const uint8_t* data = AsBytes(combined);
  size_t pos = 0;

  size_t consumed = 0;
  bool ok = framer.Feed(data, combined.size(), &consumed);
  EXPECT_TRUE(ok);
  EXPECT_TRUE(framer.is_handshake());
  EXPECT_EQ(framer.destination().host(), "8.8.8.8");
  pos += consumed;

  consumed = 0;
  ok = framer.Feed(data + pos, combined.size() - pos, &consumed);
  EXPECT_TRUE(ok);
  EXPECT_FALSE(framer.is_handshake());
  EXPECT_EQ(std::string(framer.payload()), payload);
  pos += consumed;
  EXPECT_EQ(pos, combined.size());
}

TEST(NaiveUotFramerTest, FeedHandshakeDomainMaxLength) {
  std::string domain(255, 'x');
  HostPortPair dest(domain, 65535);
  std::string frame = NaiveUotFramer::EncodeHandshake(true, dest);

  NaiveUotFramer framer;
  size_t consumed = 0;
  bool ok = framer.Feed(AsBytes(frame), frame.size(), &consumed);
  EXPECT_TRUE(ok);
  EXPECT_EQ(framer.destination().host(), domain);
  EXPECT_EQ(framer.destination().port(), 65535);
}

TEST(NaiveUotFramerTest, FeedStressRandomSplits) {
  HostPortPair dest("1.2.3.4", 53);
  std::string hs = NaiveUotFramer::EncodeHandshake(true, dest);

  std::vector<std::string> payloads;
  for (int i = 0; i < 100; i++) {
    payloads.push_back(std::string(i + 1, 'A' + (i % 26)));
  }

  std::string all = hs;
  for (auto& p : payloads) all += NaiveUotFramer::EncodeData(p);

  NaiveUotFramer framer;
  const uint8_t* data = AsBytes(all);
  size_t pos = 0;
  int payloads_decoded = 0;

  while (pos < all.size()) {
    size_t chunk = 1 + (pos * 37 + 13) % 7;
    chunk = std::min(chunk, all.size() - pos);

    size_t consumed = 0;
    while (consumed < chunk) {
      size_t c = 0;
      bool ok = framer.Feed(data + pos + consumed, chunk - consumed, &c);
      consumed += c;
      if (ok && !framer.is_handshake()) {
        EXPECT_EQ(std::string(framer.payload()), payloads[payloads_decoded]);
        payloads_decoded++;
      } else if (!ok) {
        break;
      }
    }
    pos += chunk;
  }

  EXPECT_EQ(payloads_decoded, 100);
}

// ==========================================================================
// NaiveUdpConnection: SOCKS5 UDP helper tests
// ==========================================================================

TEST(NaiveUdpConnectionSocks5Test, BuildHeaderIPv4) {
  HostPortPair dest("192.168.1.1", 53);
  std::string h = NaiveUdpConnection::BuildSocks5UdpHeader(dest);

  // RSV(2) + FRAG(1) + ATYP(1) + IP(4) + PORT(2) = 10
  EXPECT_EQ(h.size(), 10u);
  EXPECT_EQ(static_cast<uint8_t>(h[0]), 0x00);  // RSV
  EXPECT_EQ(static_cast<uint8_t>(h[1]), 0x00);  // RSV
  EXPECT_EQ(static_cast<uint8_t>(h[2]), 0x00);  // FRAG
  EXPECT_EQ(static_cast<uint8_t>(h[3]), 0x01);  // ATYP IPv4
  EXPECT_EQ(static_cast<uint8_t>(h[4]), 192);
  EXPECT_EQ(static_cast<uint8_t>(h[8]), 0x00);  // port high
  EXPECT_EQ(static_cast<uint8_t>(h[9]), 0x35);  // port low (53)
}

TEST(NaiveUdpConnectionSocks5Test, BuildHeaderIPv6) {
  HostPortPair dest("2001:db8::1", 443);
  std::string h = NaiveUdpConnection::BuildSocks5UdpHeader(dest);

  // RSV(2) + FRAG(1) + ATYP(1) + IP(16) + PORT(2) = 22
  EXPECT_EQ(h.size(), 22u);
  EXPECT_EQ(static_cast<uint8_t>(h[3]), 0x04);  // ATYP IPv6
}

TEST(NaiveUdpConnectionSocks5Test, BuildHeaderDomain) {
  HostPortPair dest("example.org", 8080);
  std::string h = NaiveUdpConnection::BuildSocks5UdpHeader(dest);

  // RSV(2) + FRAG(1) + ATYP(1) + LEN(1) + domain(11) + PORT(2) = 18
  EXPECT_EQ(h.size(), 18u);
  EXPECT_EQ(static_cast<uint8_t>(h[3]), 0x03);  // ATYP Domain
  EXPECT_EQ(static_cast<uint8_t>(h[4]), 11);
  EXPECT_EQ(h.substr(5, 11), "example.org");
}

TEST(NaiveUdpConnectionSocks5Test, ParsePacketIPv4) {
  HostPortPair dest("192.168.1.1", 53);
  std::string header = NaiveUdpConnection::BuildSocks5UdpHeader(dest);
  std::string payload = "DNS data";
  std::string packet = header + payload;

  HostPortPair parsed_dest;
  std::string_view parsed_payload;
  bool ok = NaiveUdpConnection::ParseSocks5UdpPacket(
      AsBytes(packet), packet.size(), parsed_dest, parsed_payload);

  EXPECT_TRUE(ok);
  EXPECT_EQ(parsed_dest.host(), "192.168.1.1");
  EXPECT_EQ(parsed_dest.port(), 53);
  EXPECT_EQ(std::string(parsed_payload), payload);
}

TEST(NaiveUdpConnectionSocks5Test, ParsePacketIPv6) {
  HostPortPair dest("2001:db8::1", 443);
  std::string header = NaiveUdpConnection::BuildSocks5UdpHeader(dest);
  std::string payload = "TLS data";
  std::string packet = header + payload;

  HostPortPair parsed_dest;
  std::string_view parsed_payload;
  bool ok = NaiveUdpConnection::ParseSocks5UdpPacket(
      AsBytes(packet), packet.size(), parsed_dest, parsed_payload);

  EXPECT_TRUE(ok);
  EXPECT_EQ(parsed_dest.port(), 443);
  EXPECT_EQ(std::string(parsed_payload), payload);
}

TEST(NaiveUdpConnectionSocks5Test, ParsePacketDomain) {
  HostPortPair dest("example.org", 8080);
  std::string header = NaiveUdpConnection::BuildSocks5UdpHeader(dest);
  std::string payload = "HTTP data";
  std::string packet = header + payload;

  HostPortPair parsed_dest;
  std::string_view parsed_payload;
  bool ok = NaiveUdpConnection::ParseSocks5UdpPacket(
      AsBytes(packet), packet.size(), parsed_dest, parsed_payload);

  EXPECT_TRUE(ok);
  EXPECT_EQ(parsed_dest.host(), "example.org");
  EXPECT_EQ(parsed_dest.port(), 8080);
  EXPECT_EQ(std::string(parsed_payload), payload);
}

TEST(NaiveUdpConnectionSocks5Test, ParsePacketTooShort) {
  uint8_t too_short[] = {0x00, 0x00};
  HostPortPair dest;
  std::string_view payload;
  EXPECT_FALSE(NaiveUdpConnection::ParseSocks5UdpPacket(
      too_short, 2, dest, payload));
}

TEST(NaiveUdpConnectionSocks5Test, ParsePacketInvalidRSV) {
  uint8_t bad[] = {0x01, 0x00, 0x00, 0x01, 1, 2, 3, 4, 0, 53};
  HostPortPair dest;
  std::string_view payload;
  EXPECT_FALSE(NaiveUdpConnection::ParseSocks5UdpPacket(
      bad, sizeof(bad), dest, payload));
}

TEST(NaiveUdpConnectionSocks5Test, ParsePacketInvalidFRAG) {
  uint8_t bad[] = {0x00, 0x00, 0x01, 0x01, 1, 2, 3, 4, 0, 53};
  HostPortPair dest;
  std::string_view payload;
  EXPECT_FALSE(NaiveUdpConnection::ParseSocks5UdpPacket(
      bad, sizeof(bad), dest, payload));
}

TEST(NaiveUdpConnectionSocks5Test, ParsePacketInvalidATYP) {
  uint8_t bad[] = {0x00, 0x00, 0x00, 0x05};
  HostPortPair dest;
  std::string_view payload;
  EXPECT_FALSE(NaiveUdpConnection::ParseSocks5UdpPacket(
      bad, sizeof(bad), dest, payload));
}

TEST(NaiveUdpConnectionSocks5Test, ParsePacketIPv4TooShort) {
  uint8_t too_short[] = {0x00, 0x00, 0x00, 0x01, 1, 2};
  HostPortPair dest;
  std::string_view payload;
  EXPECT_FALSE(NaiveUdpConnection::ParseSocks5UdpPacket(
      too_short, sizeof(too_short), dest, payload));
}

TEST(NaiveUdpConnectionSocks5Test, ParsePacketIPv6TooShort) {
  uint8_t too_short[] = {0x00, 0x00, 0x00, 0x04, 1, 2, 3, 4};
  HostPortPair dest;
  std::string_view payload;
  EXPECT_FALSE(NaiveUdpConnection::ParseSocks5UdpPacket(
      too_short, sizeof(too_short), dest, payload));
}

TEST(NaiveUdpConnectionSocks5Test, ParsePacketDomainTooShort) {
  uint8_t too_short[] = {0x00, 0x00, 0x00, 0x03, 10, 'a', 'b'};
  HostPortPair dest;
  std::string_view payload;
  EXPECT_FALSE(NaiveUdpConnection::ParseSocks5UdpPacket(
      too_short, sizeof(too_short), dest, payload));
}

TEST(NaiveUdpConnectionSocks5Test, RoundTripIPv4) {
  HostPortPair dest("10.0.0.1", 9999);
  std::string payload = "test data for round trip";
  std::string packet = NaiveUdpConnection::BuildSocks5UdpHeader(dest) + payload;

  HostPortPair parsed_dest;
  std::string_view parsed_payload;
  bool ok = NaiveUdpConnection::ParseSocks5UdpPacket(
      AsBytes(packet), packet.size(), parsed_dest, parsed_payload);

  EXPECT_TRUE(ok);
  EXPECT_EQ(parsed_dest.host(), dest.host());
  EXPECT_EQ(parsed_dest.port(), dest.port());
  EXPECT_EQ(std::string(parsed_payload), payload);
}

TEST(NaiveUdpConnectionSocks5Test, RoundTripBinaryPayload) {
  HostPortPair dest("1.2.3.4", 53);
  std::string payload;
  for (int i = 0; i < 256; i++) payload.push_back(static_cast<char>(i));
  std::string packet = NaiveUdpConnection::BuildSocks5UdpHeader(dest) + payload;

  HostPortPair parsed_dest;
  std::string_view parsed_payload;
  bool ok = NaiveUdpConnection::ParseSocks5UdpPacket(
      AsBytes(packet), packet.size(), parsed_dest, parsed_payload);

  EXPECT_TRUE(ok);
  EXPECT_EQ(parsed_dest.host(), "1.2.3.4");
  EXPECT_EQ(parsed_dest.port(), 53);
  EXPECT_EQ(parsed_payload.size(), 256u);
  for (int i = 0; i < 256; i++) {
    EXPECT_EQ(static_cast<uint8_t>(parsed_payload[i]), static_cast<uint8_t>(i));
  }
}

// ==========================================================================
// Full pipeline tests (UoT framer + SOCKS5 helpers)
// ==========================================================================

TEST(NaiveUotPipelineTest, ClientToServer) {
  HostPortPair dest("8.8.8.8", 53);
  std::string dns_query = "\x00\x01\x00\x00\x00\x01\x00\x00";

  // Client sends SOCKS5 UDP packet
  std::string socks5_packet =
      NaiveUdpConnection::BuildSocks5UdpHeader(dest) + dns_query;

  // Parse SOCKS5
  HostPortPair parsed_dest;
  std::string_view parsed_payload;
  ASSERT_TRUE(NaiveUdpConnection::ParseSocks5UdpPacket(
      AsBytes(socks5_packet), socks5_packet.size(),
      parsed_dest, parsed_payload));
  EXPECT_EQ(parsed_dest.host(), "8.8.8.8");

  // Encode UoT handshake + data
  std::string uot_hs = NaiveUotFramer::EncodeHandshake(true, parsed_dest);
  std::string uot_data = NaiveUotFramer::EncodeData(parsed_payload);

  // Decode UoT
  NaiveUotFramer framer;
  size_t consumed = 0;
  ASSERT_TRUE(framer.Feed(AsBytes(uot_hs), uot_hs.size(), &consumed));
  EXPECT_TRUE(framer.is_handshake());
  EXPECT_EQ(framer.destination().host(), "8.8.8.8");

  consumed = 0;
  ASSERT_TRUE(framer.Feed(AsBytes(uot_data), uot_data.size(), &consumed));
  EXPECT_EQ(std::string(framer.payload()), dns_query);
}

TEST(NaiveUotPipelineTest, ServerToClient) {
  HostPortPair dest("8.8.8.8", 53);
  std::string dns_response = "\x00\x01\x00\x01\x00\x01\x00\x01";

  // Set up framer with handshake done
  std::string hs = NaiveUotFramer::EncodeHandshake(true, dest);
  NaiveUotFramer framer;
  size_t consumed = 0;
  framer.Feed(AsBytes(hs), hs.size(), &consumed);

  // Decode UoT data frame
  std::string uot_data = NaiveUotFramer::EncodeData(dns_response);
  consumed = 0;
  ASSERT_TRUE(framer.Feed(AsBytes(uot_data), uot_data.size(), &consumed));

  // Wrap in SOCKS5 and parse
  std::string socks5_packet =
      NaiveUdpConnection::BuildSocks5UdpHeader(framer.destination()) +
      std::string(framer.payload());

  HostPortPair parsed_dest;
  std::string_view parsed_payload;
  ASSERT_TRUE(NaiveUdpConnection::ParseSocks5UdpPacket(
      AsBytes(socks5_packet), socks5_packet.size(),
      parsed_dest, parsed_payload));
  EXPECT_EQ(parsed_dest.host(), "8.8.8.8");
  EXPECT_EQ(std::string(parsed_payload), dns_response);
}

}  // namespace net
