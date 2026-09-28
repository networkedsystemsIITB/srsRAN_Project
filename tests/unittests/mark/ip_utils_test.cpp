/*
 *
 * Copyright 2021-2025 Software Radio Systems Limited
 *
 * This file is part of srsRAN.
 *
 * srsRAN is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * srsRAN is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * A copy of the GNU Affero General Public License can be found in
 * the LICENSE file in the top-level directory of this distribution
 * and at http://www.gnu.org/licenses/.
 *
 */

#include "lib/mark/ip_utils.h"
#include <gtest/gtest.h>
#include <vector>

using namespace srsran;
using namespace srs_cu_up::ip;

namespace {

// Helper to construct a basic IPv4 UDP packet
std::vector<uint8_t> make_ipv4_udp_packet(ecn_codepoint ecn, uint16_t payload_len)
{
  uint16_t             total_len = 20 + 8 + payload_len;
  std::vector<uint8_t> pkt(total_len, 0);

  // IPv4 header
  pkt[0] = 0x45; // Version 4, IHL 5 (20 bytes)
  pkt[1] = static_cast<uint8_t>(ecn);
  pkt[2] = total_len >> 8;
  pkt[3] = total_len & 0xff;
  pkt[4] = 0x12; // ID
  pkt[5] = 0x34;
  pkt[6] = 0x40; // DF flag
  pkt[7] = 0x00;
  pkt[8] = 64; // TTL
  pkt[9] = IP_PROTO_UDP;
  // src: 10.0.0.1
  pkt[12] = 10;
  pkt[13] = 0;
  pkt[14] = 0;
  pkt[15] = 1;
  // dst: 10.0.0.2
  pkt[16] = 10;
  pkt[17] = 0;
  pkt[18] = 0;
  pkt[19] = 2;

  uint16_t ip_csum = compute_checksum(pkt.data(), 20);
  pkt[10]          = ip_csum >> 8;
  pkt[11]          = ip_csum & 0xff;

  // UDP header
  uint16_t udp_len = 8 + payload_len;
  pkt[20]          = 0x04;
  pkt[21]          = 0xd2; // src port 1234
  pkt[22]          = 0x16;
  pkt[23]          = 0x2e; // dst port 5678
  pkt[24]          = udp_len >> 8;
  pkt[25]          = udp_len & 0xff;
  pkt[26]          = 0x00;
  pkt[27]          = 0x00; // checksum 0 (valid for UDP)

  for (size_t i = 0; i < payload_len; ++i) {
    pkt[28 + i] = static_cast<uint8_t>(i & 0xff);
  }

  return pkt;
}

// Helper to construct a basic IPv4 TCP packet with optional AccECN option
std::vector<uint8_t> make_ipv4_tcp_packet(ecn_codepoint ecn,
                                          uint8_t       ihl_words,
                                          uint8_t       opt_kind,
                                          uint8_t       opt_len,
                                          bool          ack_flag,
                                          uint32_t      ack_seq,
                                          uint16_t      payload_len)
{
  uint8_t ihl_bytes   = ihl_words * 4;
  uint8_t tcp_hdr_len = 20;
  if (opt_len > 0) {
    // Pad to multiple of 4 bytes
    uint8_t padded_opt_len = ((opt_len + 3) / 4) * 4;
    tcp_hdr_len += padded_opt_len;
  }
  uint16_t             total_len = ihl_bytes + tcp_hdr_len + payload_len;
  std::vector<uint8_t> pkt(total_len, 0);

  // IPv4 header
  pkt[0]  = 0x40 | (ihl_words & 0x0f);
  pkt[1]  = static_cast<uint8_t>(ecn);
  pkt[2]  = total_len >> 8;
  pkt[3]  = total_len & 0xff;
  pkt[4]  = 0x56;
  pkt[5]  = 0x78; // ID
  pkt[6]  = 0x40;
  pkt[7]  = 0x00; // DF
  pkt[8]  = 64;
  pkt[9]  = IP_PROTO_TCP;
  pkt[12] = 192;
  pkt[13] = 168;
  pkt[14] = 1;
  pkt[15] = 10;
  pkt[16] = 192;
  pkt[17] = 168;
  pkt[18] = 1;
  pkt[19] = 20;

  // If IHL > 5, fill IP options with NOP (0x01)
  for (size_t i = 20; i < ihl_bytes; ++i) {
    pkt[i] = 0x01;
  }

  uint16_t ip_csum = compute_checksum(pkt.data(), ihl_bytes);
  pkt[10]          = ip_csum >> 8;
  pkt[11]          = ip_csum & 0xff;

  // TCP header
  size_t tcp_off    = ihl_bytes;
  pkt[tcp_off + 0]  = 0x1f;
  pkt[tcp_off + 1]  = 0x90; // src port 8080
  pkt[tcp_off + 2]  = 0x01;
  pkt[tcp_off + 3]  = 0xbb; // dst port 443
  pkt[tcp_off + 4]  = 0x00;
  pkt[tcp_off + 5]  = 0x00;
  pkt[tcp_off + 6]  = 0x03;
  pkt[tcp_off + 7]  = 0xe8; // seq 1000
  pkt[tcp_off + 8]  = ack_seq >> 24;
  pkt[tcp_off + 9]  = (ack_seq >> 16) & 0xff;
  pkt[tcp_off + 10] = (ack_seq >> 8) & 0xff;
  pkt[tcp_off + 11] = ack_seq & 0xff;

  uint8_t tcp_doff  = tcp_hdr_len / 4;
  pkt[tcp_off + 12] = (tcp_doff << 4);
  pkt[tcp_off + 13] = ack_flag ? 0x10 : 0x00; // ACK flag
  pkt[tcp_off + 14] = 0x01;
  pkt[tcp_off + 15] = 0x00; // window 256

  if (opt_len > 0) {
    pkt[tcp_off + 20] = opt_kind;
    pkt[tcp_off + 21] = opt_len;
    // fill counter bytes with some non-zero initial values
    for (size_t i = 2; i < opt_len; ++i) {
      pkt[tcp_off + 20 + i] = static_cast<uint8_t>(i * 11);
    }
    // fill padding with NOP
    uint8_t padded_opt_len = ((opt_len + 3) / 4) * 4;
    for (size_t i = opt_len; i < padded_opt_len; ++i) {
      pkt[tcp_off + 20 + i] = TCP_OPT_NOP;
    }
  }

  for (size_t i = 0; i < payload_len; ++i) {
    pkt[tcp_off + tcp_hdr_len + i] = static_cast<uint8_t>(0xaa + i);
  }

  // Compute full TCP checksum
  byte_buffer temp_buf = byte_buffer::create(pkt).value();
  uint16_t    tcp_csum = compute_tcp_checksum(temp_buf, 0, ihl_bytes, tcp_hdr_len + payload_len);
  pkt[tcp_off + 16]    = tcp_csum >> 8;
  pkt[tcp_off + 17]    = tcp_csum & 0xff;

  return pkt;
}

} // namespace

TEST(ip_utils_test, parse_udp_packet)
{
  auto        raw = make_ipv4_udp_packet(ecn_codepoint::ect_1, 32);
  byte_buffer buf = byte_buffer::create(raw).value();

  parsed_packet pkt = parse_packet(buf);
  EXPECT_TRUE(pkt.is_valid);
  EXPECT_TRUE(pkt.is_ipv4);
  EXPECT_FALSE(pkt.is_fragment);
  EXPECT_EQ(pkt.ihl_bytes, 20);
  EXPECT_EQ(pkt.ecn, ecn_codepoint::ect_1);
  EXPECT_EQ(pkt.protocol, IP_PROTO_UDP);
  EXPECT_TRUE(pkt.is_udp);
  EXPECT_FALSE(pkt.is_tcp);
  EXPECT_EQ(pkt.tuple.src_port, 1234);
  EXPECT_EQ(pkt.tuple.dst_port, 5678);
  EXPECT_EQ(pkt.l4_payload_len, 32);

  // Five tuple reversal
  five_tuple rev = reverse_five_tuple(pkt.tuple);
  EXPECT_EQ(rev.src_port, 5678);
  EXPECT_EQ(rev.dst_port, 1234);
  EXPECT_EQ(rev.src_addr, pkt.tuple.dst_addr);
  EXPECT_EQ(rev.dst_addr, pkt.tuple.src_addr);
}

TEST(ip_utils_test, parse_tcp_packet_with_options)
{
  auto        raw = make_ipv4_tcp_packet(ecn_codepoint::ect_0, 5, TCP_OPT_ACCECN1, 11, true, 5000, 40);
  byte_buffer buf = byte_buffer::create(raw).value();

  parsed_packet pkt = parse_packet(buf);
  EXPECT_TRUE(pkt.is_valid);
  EXPECT_TRUE(pkt.is_ipv4);
  EXPECT_FALSE(pkt.is_fragment);
  EXPECT_EQ(pkt.ihl_bytes, 20);
  EXPECT_EQ(pkt.ecn, ecn_codepoint::ect_0);
  EXPECT_TRUE(pkt.is_tcp);
  EXPECT_TRUE(pkt.tcp_ack);
  EXPECT_FALSE(pkt.tcp_syn);
  EXPECT_EQ(pkt.ack_seq, 5000);
  EXPECT_EQ(pkt.tcp_doff_bytes, 32); // 20 + 12 padded
  EXPECT_EQ(pkt.l4_payload_len, 40);
}

TEST(ip_utils_test, parse_ihl_greater_than_5)
{
  // IHL = 6 (24 bytes IPv4 header)
  auto        raw = make_ipv4_tcp_packet(ecn_codepoint::not_ect, 6, 0, 0, false, 0, 10);
  byte_buffer buf = byte_buffer::create(raw).value();

  parsed_packet pkt = parse_packet(buf);
  EXPECT_TRUE(pkt.is_valid);
  EXPECT_EQ(pkt.ihl_bytes, 24);
  EXPECT_TRUE(pkt.is_tcp);
  EXPECT_EQ(pkt.tuple.src_port, 8080);
  EXPECT_EQ(pkt.tuple.dst_port, 443);
}

TEST(ip_utils_test, non_ipv4_and_fragmented)
{
  // IPv6 packet
  std::vector<uint8_t> v6(40, 0);
  v6[0]                = 0x60; // Version 6
  byte_buffer   v6_buf = byte_buffer::create(v6).value();
  parsed_packet pkt_v6 = parse_packet(v6_buf);
  EXPECT_FALSE(pkt_v6.is_ipv4);
  EXPECT_FALSE(pkt_v6.is_valid);

  // Fragmented IPv4 packet (MF flag set)
  auto raw               = make_ipv4_udp_packet(ecn_codepoint::not_ect, 20);
  raw[6]                 = 0x20; // MF flag set
  byte_buffer   frag_buf = byte_buffer::create(raw).value();
  parsed_packet pkt_frag = parse_packet(frag_buf);
  EXPECT_TRUE(pkt_frag.is_ipv4);
  EXPECT_TRUE(pkt_frag.is_fragment);
}

TEST(ip_utils_test, segmented_buffer_handling)
{
  // Use payload size > 2048 to ensure byte_buffer spans multiple segments
  auto        raw = make_ipv4_tcp_packet(ecn_codepoint::ect_1, 5, TCP_OPT_ACCECN0, 11, true, 2000, 4000);
  byte_buffer buf = byte_buffer::create(raw).value();

  EXPECT_EQ(buf.length(), raw.size());
  EXPECT_FALSE(buf.is_contiguous());

  parsed_packet pkt = parse_packet(buf);
  EXPECT_TRUE(pkt.is_valid);
  EXPECT_EQ(pkt.ecn, ecn_codepoint::ect_1);
  EXPECT_EQ(pkt.tuple.src_port, 8080);
  EXPECT_EQ(pkt.ack_seq, 2000);

  // Incremental IP checksum check on segmented buffer
  EXPECT_TRUE(set_ip_ecn(buf, 0, ecn_codepoint::ce));
  EXPECT_EQ(buf[1] & INET_ECN_MASK, ecn_codepoint::ce);
  uint16_t new_ip_csum      = (static_cast<uint16_t>(buf[10]) << 8) | buf[11];
  uint16_t expected_ip_csum = compute_ip_checksum(buf, 0, pkt.ihl_bytes);
  EXPECT_EQ(new_ip_csum, expected_ip_csum);
}

TEST(ip_utils_test, set_ip_ecn_incremental_checksum)
{
  for (auto initial_ecn : {ecn_codepoint::not_ect, ecn_codepoint::ect_0, ecn_codepoint::ect_1}) {
    auto        raw = make_ipv4_udp_packet(initial_ecn, 16);
    byte_buffer buf = byte_buffer::create(raw).value();

    EXPECT_TRUE(set_ip_ecn(buf, 0, ecn_codepoint::ce));
    EXPECT_EQ(buf[1] & INET_ECN_MASK, ecn_codepoint::ce);

    uint16_t inc_csum  = (static_cast<uint16_t>(buf[10]) << 8) | buf[11];
    uint16_t full_csum = compute_ip_checksum(buf, 0, 20);
    EXPECT_EQ(inc_csum, full_csum);
  }
}

TEST(ip_utils_test, accecn_ace_rewrite_incremental_checksum)
{
  auto        raw = make_ipv4_tcp_packet(ecn_codepoint::ect_1, 5, 0, 0, true, 10000, 0);
  byte_buffer buf = byte_buffer::create(raw).value();

  // Test rewriting ACE bits with various counter values
  for (size_t ce_cnt : {1u, 2u, 3u, 5u, 7u}) {
    accecn_counters cnt{};
    cnt.ce_pkt = ce_cnt;

    EXPECT_TRUE(rewrite_accecn_feedback(buf, 0, 20, cnt));

    uint8_t b12           = buf[32]; // 20 + 12
    uint8_t b13           = buf[33]; // 20 + 13
    uint8_t ace_recovered = ((b12 & 0x01) ? 4 : 0) | ((b13 & 0x80) ? 2 : 0) | ((b13 & 0x40) ? 1 : 0);
    EXPECT_EQ(ace_recovered, ce_cnt & 0x07);
    // Data offset and reserved bits are untouched.
    EXPECT_EQ(b12 & 0xfe, raw[32] & 0xfe);

    uint16_t inc_csum  = (static_cast<uint16_t>(buf[36]) << 8) | buf[37];
    uint16_t full_csum = compute_tcp_checksum(buf, 0, 20, 20);
    EXPECT_EQ(inc_csum, full_csum);
  }
}

TEST(ip_utils_test, accecn_option_rewrite_lengths)
{
  accecn_counters cnt{};
  cnt.ce_pkt     = 6;
  cnt.ecn0_bytes = 0x112233;
  cnt.ecn1_bytes = 0x445566;
  cnt.ce_bytes   = 0x778899;

  // Test option lengths 2, 5, 8, 11 for Kind 174 (AccECN1)
  for (uint8_t opt_len : {2, 5, 8, 11}) {
    auto        raw = make_ipv4_tcp_packet(ecn_codepoint::ect_1, 5, TCP_OPT_ACCECN1, opt_len, true, 12345, 0);
    byte_buffer buf = byte_buffer::create(raw).value();

    uint8_t tcp_hdr_len = ((opt_len + 3) / 4) * 4 + 20;

    EXPECT_TRUE(rewrite_accecn_feedback(buf, 0, 20, cnt));

    if (opt_len >= 5) {
      // First counter for 174 is ecn1_bytes
      EXPECT_EQ(buf[42], 0x44);
      EXPECT_EQ(buf[43], 0x55);
      EXPECT_EQ(buf[44], 0x66);
    }
    if (opt_len >= 8) {
      // Second counter is ce_bytes
      EXPECT_EQ(buf[45], 0x77);
      EXPECT_EQ(buf[46], 0x88);
      EXPECT_EQ(buf[47], 0x99);
    }
    if (opt_len >= 11) {
      // Third counter is ecn0_bytes
      EXPECT_EQ(buf[48], 0x11);
      EXPECT_EQ(buf[49], 0x22);
      EXPECT_EQ(buf[50], 0x33);
    }

    uint16_t inc_csum  = (static_cast<uint16_t>(buf[36]) << 8) | buf[37];
    uint16_t full_csum = compute_tcp_checksum(buf, 0, 20, tcp_hdr_len);
    EXPECT_EQ(inc_csum, full_csum);
  }

  // Test option lengths 2, 5, 8, 11 for Kind 172 (AccECN0)
  for (uint8_t opt_len : {2, 5, 8, 11}) {
    auto        raw = make_ipv4_tcp_packet(ecn_codepoint::ect_0, 5, TCP_OPT_ACCECN0, opt_len, true, 12345, 0);
    byte_buffer buf = byte_buffer::create(raw).value();

    uint8_t tcp_hdr_len = ((opt_len + 3) / 4) * 4 + 20;

    EXPECT_TRUE(rewrite_accecn_feedback(buf, 0, 20, cnt));

    if (opt_len >= 5) {
      // First counter for 172 is ecn0_bytes
      EXPECT_EQ(buf[42], 0x11);
      EXPECT_EQ(buf[43], 0x22);
      EXPECT_EQ(buf[44], 0x33);
    }
    if (opt_len >= 8) {
      // Second counter is ce_bytes
      EXPECT_EQ(buf[45], 0x77);
      EXPECT_EQ(buf[46], 0x88);
      EXPECT_EQ(buf[47], 0x99);
    }
    if (opt_len >= 11) {
      // Third counter is ecn1_bytes
      EXPECT_EQ(buf[48], 0x44);
      EXPECT_EQ(buf[49], 0x55);
      EXPECT_EQ(buf[50], 0x66);
    }

    uint16_t inc_csum  = (static_cast<uint16_t>(buf[36]) << 8) | buf[37];
    uint16_t full_csum = compute_tcp_checksum(buf, 0, 20, tcp_hdr_len);
    EXPECT_EQ(inc_csum, full_csum);
  }
}
