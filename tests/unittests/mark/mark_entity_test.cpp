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
#include "lib/mark/mark_entity_impl.h"
#include "srsran/mark/mark_factory.h"
#include <gtest/gtest.h>
#include <queue>
#include <vector>

using namespace srsran;
using namespace srs_cu_up;

namespace {

class test_mark_rx_sdu_notifier : public mark_rx_sdu_notifier
{
public:
  struct item {
    byte_buffer   sdu;
    qos_flow_id_t qfi;
  };
  std::queue<item> received_sdus;

  void on_new_sdu(byte_buffer sdu, qos_flow_id_t qfi) override { received_sdus.push({std::move(sdu), qfi}); }
};

class test_mark_tx_pdu_notifier : public mark_tx_pdu_notifier
{
public:
  struct item {
    byte_buffer   pdu;
    qos_flow_id_t qfi;
  };
  std::queue<item> received_pdus;

  void on_new_pdu(byte_buffer pdu, qos_flow_id_t qfi) override { received_pdus.push({std::move(pdu), qfi}); }
};

// Helper to construct a basic IPv4 UDP packet
std::vector<uint8_t> make_ipv4_udp(ip::ecn_codepoint ecn, uint16_t payload_len)
{
  uint16_t             total_len = 20 + 8 + payload_len;
  std::vector<uint8_t> pkt(total_len, 0);

  pkt[0]  = 0x45;
  pkt[1]  = static_cast<uint8_t>(ecn);
  pkt[2]  = total_len >> 8;
  pkt[3]  = total_len & 0xff;
  pkt[4]  = 0x12;
  pkt[5]  = 0x34;
  pkt[6]  = 0x40;
  pkt[7]  = 0x00;
  pkt[8]  = 64;
  pkt[9]  = ip::IP_PROTO_UDP;
  pkt[12] = 10;
  pkt[13] = 0;
  pkt[14] = 0;
  pkt[15] = 1;
  pkt[16] = 10;
  pkt[17] = 0;
  pkt[18] = 0;
  pkt[19] = 2;

  uint16_t ip_csum = ip::compute_checksum(pkt.data(), 20);
  pkt[10]          = ip_csum >> 8;
  pkt[11]          = ip_csum & 0xff;

  uint16_t udp_len = 8 + payload_len;
  pkt[20]          = 0x04;
  pkt[21]          = 0xd2; // src 1234
  pkt[22]          = 0x16;
  pkt[23]          = 0x2e; // dst 5678
  pkt[24]          = udp_len >> 8;
  pkt[25]          = udp_len & 0xff;
  pkt[26]          = 0;
  pkt[27]          = 0;

  for (size_t i = 0; i < payload_len; ++i) {
    pkt[28 + i] = static_cast<uint8_t>(i & 0xff);
  }
  return pkt;
}

// Helper to construct a basic IPv4 TCP packet with optional AccECN option
std::vector<uint8_t> make_ipv4_tcp(ip::ecn_codepoint ecn,
                                   uint32_t          src_ip,
                                   uint32_t          dst_ip,
                                   uint16_t          src_port,
                                   uint16_t          dst_port,
                                   bool              syn,
                                   bool              ack,
                                   uint32_t          seq,
                                   uint32_t          ack_seq,
                                   uint8_t           opt_kind,
                                   uint8_t           opt_len,
                                   uint16_t          payload_len)
{
  uint8_t tcp_hdr_len = 20;
  if (opt_len > 0) {
    uint8_t padded_opt_len = ((opt_len + 3) / 4) * 4;
    tcp_hdr_len += padded_opt_len;
  }
  uint16_t             total_len = 20 + tcp_hdr_len + payload_len;
  std::vector<uint8_t> pkt(total_len, 0);

  pkt[0]  = 0x45;
  pkt[1]  = static_cast<uint8_t>(ecn);
  pkt[2]  = total_len >> 8;
  pkt[3]  = total_len & 0xff;
  pkt[4]  = 0xab;
  pkt[5]  = 0xcd;
  pkt[6]  = 0x40;
  pkt[7]  = 0x00;
  pkt[8]  = 64;
  pkt[9]  = ip::IP_PROTO_TCP;
  pkt[12] = (src_ip >> 24) & 0xff;
  pkt[13] = (src_ip >> 16) & 0xff;
  pkt[14] = (src_ip >> 8) & 0xff;
  pkt[15] = src_ip & 0xff;
  pkt[16] = (dst_ip >> 24) & 0xff;
  pkt[17] = (dst_ip >> 16) & 0xff;
  pkt[18] = (dst_ip >> 8) & 0xff;
  pkt[19] = dst_ip & 0xff;

  uint16_t ip_csum = ip::compute_checksum(pkt.data(), 20);
  pkt[10]          = ip_csum >> 8;
  pkt[11]          = ip_csum & 0xff;

  pkt[20] = src_port >> 8;
  pkt[21] = src_port & 0xff;
  pkt[22] = dst_port >> 8;
  pkt[23] = dst_port & 0xff;
  pkt[24] = seq >> 24;
  pkt[25] = (seq >> 16) & 0xff;
  pkt[26] = (seq >> 8) & 0xff;
  pkt[27] = seq & 0xff;
  pkt[28] = ack_seq >> 24;
  pkt[29] = (ack_seq >> 16) & 0xff;
  pkt[30] = (ack_seq >> 8) & 0xff;
  pkt[31] = ack_seq & 0xff;

  uint8_t tcp_doff = tcp_hdr_len / 4;
  pkt[32]          = (tcp_doff << 4);
  pkt[33]          = (ack ? 0x10 : 0x00) | (syn ? 0x02 : 0x00);
  pkt[34]          = 0x01;
  pkt[35]          = 0x00;

  if (opt_len > 0) {
    pkt[40] = opt_kind;
    pkt[41] = opt_len;
    for (size_t i = 2; i < opt_len; ++i) {
      pkt[40 + i] = static_cast<uint8_t>(i);
    }
    uint8_t padded_opt_len = ((opt_len + 3) / 4) * 4;
    for (size_t i = opt_len; i < padded_opt_len; ++i) {
      pkt[40 + i] = ip::TCP_OPT_NOP;
    }
  }

  for (size_t i = 0; i < payload_len; ++i) {
    pkt[20 + tcp_hdr_len + i] = static_cast<uint8_t>(0x55);
  }

  byte_buffer temp_buf = byte_buffer::create(pkt).value();
  uint16_t    tcp_csum = ip::compute_tcp_checksum(temp_buf, 0, 20, tcp_hdr_len + payload_len);
  pkt[36]              = tcp_csum >> 8;
  pkt[37]              = tcp_csum & 0xff;

  return pkt;
}

class mark_entity_test : public ::testing::Test
{
protected:
  void SetUp() override
  {
    msg.ue_index        = 0;
    msg.pdu_session_id  = pdu_session_id_t::min;
    msg.rx_sdu_notifier = &rx_notifier;
    msg.tx_pdu_notifier = &tx_notifier;
    mark                = create_mark(msg);
    mark_impl           = static_cast<mark_entity_impl*>(mark.get());
    mark_impl->add_drb(drb_id_t::drb1, 12);
    mark_impl->add_mapping(qos_flow_id_t::min, drb_id_t::drb1);
  }

  /// Recreates the entity with a different configuration.
  void recreate(const mark_config& new_cfg)
  {
    cfg       = new_cfg;
    mark      = create_mark(msg);
    mark_impl = static_cast<mark_entity_impl*>(mark.get());
    mark_impl->add_drb(drb_id_t::drb1, 12);
    mark_impl->add_mapping(qos_flow_id_t::min, drb_id_t::drb1);
  }

  /// Sends one DL TCP data packet of the server->UE flow used by the ACK tests.
  void send_dl_tcp(ip::ecn_codepoint ecn, uint32_t seq)
  {
    auto pkt = make_ipv4_tcp(ecn, server_ip, ue_ip, 8080, 5001, false, true, seq, 1, 0, 0, 1336);
    mark->get_mark_tx_sdu_handler().handle_sdu(byte_buffer::create(pkt).value(), qos_flow_id_t::min);
  }

  /// Sends one UL ACK with an AccECN option of the UE->server flow and returns what MARK forwarded.
  std::pair<std::vector<uint8_t>, byte_buffer> send_ul_ack(ip::ecn_codepoint ecn)
  {
    auto ack = make_ipv4_tcp(ecn, ue_ip, server_ip, 5001, 8080, false, true, 1, 3672, ip::TCP_OPT_ACCECN0, 11, 0);
    mark->get_mark_rx_pdu_handler().handle_pdu(byte_buffer::create(ack).value(), qos_flow_id_t::min);
    byte_buffer out = std::move(rx_notifier.received_sdus.front().sdu);
    rx_notifier.received_sdus.pop();
    return {ack, std::move(out)};
  }

  static constexpr uint32_t server_ip = 0x0a000001;
  static constexpr uint32_t ue_ip     = 0x0a000002;

  mark_config                  cfg;
  std::atomic<uint32_t>        nof_ues{1};
  test_mark_rx_sdu_notifier    rx_notifier;
  test_mark_tx_pdu_notifier    tx_notifier;
  mark_entity_creation_message msg{0, pdu_session_id_t::min, &rx_notifier, &tx_notifier, cfg, nof_ues};
  std::unique_ptr<mark_entity> mark;
  mark_entity_impl*            mark_impl = nullptr;
};

} // namespace

TEST_F(mark_entity_test, creation)
{
  ASSERT_NE(mark, nullptr);
}

TEST_F(mark_entity_test, dl_pass_through)
{
  const std::array<uint8_t, 8> data = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
  byte_buffer                  sdu  = byte_buffer::create(data).value();

  mark->get_mark_tx_sdu_handler().handle_sdu(sdu.deep_copy().value(), qos_flow_id_t::min);

  ASSERT_EQ(tx_notifier.received_pdus.size(), 1u);
  auto item = std::move(tx_notifier.received_pdus.front());
  tx_notifier.received_pdus.pop();

  EXPECT_EQ(item.qfi, qos_flow_id_t::min);
  EXPECT_EQ(item.pdu.length(), data.size());
  EXPECT_EQ(item.pdu, data);
}

TEST_F(mark_entity_test, ul_pass_through)
{
  const std::array<uint8_t, 8> data = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80};
  byte_buffer                  pdu  = byte_buffer::create(data).value();

  mark->get_mark_rx_pdu_handler().handle_pdu(pdu.deep_copy().value(), qos_flow_id_t::min);

  ASSERT_EQ(rx_notifier.received_sdus.size(), 1u);
  auto item = std::move(rx_notifier.received_sdus.front());
  rx_notifier.received_sdus.pop();

  EXPECT_EQ(item.qfi, qos_flow_id_t::min);
  EXPECT_EQ(item.sdu.length(), data.size());
  EXPECT_EQ(item.sdu, data);
}

TEST_F(mark_entity_test, dl_udp_marking_forced_p1)
{
  mark_impl->set_forced_l4s_prob(1.0);
  auto        raw_pkt = make_ipv4_udp(ip::ecn_codepoint::ect_1, 64);
  byte_buffer sdu     = byte_buffer::create(raw_pkt).value();

  mark->get_mark_tx_sdu_handler().handle_sdu(std::move(sdu), qos_flow_id_t::min);

  ASSERT_EQ(tx_notifier.received_pdus.size(), 1u);
  auto item = std::move(tx_notifier.received_pdus.front());
  tx_notifier.received_pdus.pop();

  auto parsed = ip::parse_packet(item.pdu);
  EXPECT_TRUE(parsed.is_valid);
  EXPECT_EQ(parsed.ecn, ip::ecn_codepoint::ce);
  EXPECT_EQ(parsed.ip_check, ip::compute_ip_checksum(item.pdu, 0, parsed.ihl_bytes));

  // UDP has no ACKs to rewrite, so it is not tracked in the flow table.
  EXPECT_EQ(mark_impl->get_flow_table().size(), 0u);
}

TEST_F(mark_entity_test, dl_udp_marking_forced_p0)
{
  mark_impl->set_forced_l4s_prob(0.0);
  auto        raw_pkt = make_ipv4_udp(ip::ecn_codepoint::ect_1, 64);
  byte_buffer sdu     = byte_buffer::create(raw_pkt).value();

  mark->get_mark_tx_sdu_handler().handle_sdu(std::move(sdu), qos_flow_id_t::min);

  ASSERT_EQ(tx_notifier.received_pdus.size(), 1u);
  auto item = std::move(tx_notifier.received_pdus.front());
  tx_notifier.received_pdus.pop();

  auto parsed = ip::parse_packet(item.pdu);
  EXPECT_TRUE(parsed.is_valid);
  EXPECT_EQ(parsed.ecn, ip::ecn_codepoint::ect_1);
  EXPECT_EQ(parsed.ip_check, ip::compute_ip_checksum(item.pdu, 0, parsed.ihl_bytes));

  EXPECT_EQ(mark_impl->get_flow_table().size(), 0u);
}

TEST_F(mark_entity_test, dl_tcp_virtual_ce)
{
  mark_impl->set_forced_l4s_prob(1.0);
  uint32_t s_ip    = 0x0a000001; // 10.0.0.1
  uint32_t d_ip    = 0x0a000002; // 10.0.0.2
  auto     raw_pkt = make_ipv4_tcp(ip::ecn_codepoint::ect_1, s_ip, d_ip, 8080, 5001, false, true, 1000, 1, 0, 0, 100);
  byte_buffer sdu  = byte_buffer::create(raw_pkt).value();

  mark->get_mark_tx_sdu_handler().handle_sdu(std::move(sdu), qos_flow_id_t::min);

  ASSERT_EQ(tx_notifier.received_pdus.size(), 1u);
  auto item = std::move(tx_notifier.received_pdus.front());
  tx_notifier.received_pdus.pop();

  // On the wire, DL TCP is NOT rewritten (virtual-CE marked only)
  auto parsed = ip::parse_packet(item.pdu);
  EXPECT_TRUE(parsed.is_valid);
  EXPECT_EQ(parsed.ecn, ip::ecn_codepoint::ect_1);

  // But flow table reflects virtual CE
  auto flow = mark_impl->get_flow_table().get_flow(parsed.tuple);
  ASSERT_TRUE(flow.has_value());
  EXPECT_EQ(flow->pkts_with_ce, cfg.ack_rewrite.ce_pkt_offset + 1);
  EXPECT_EQ(flow->bytes_with_ce, 100u);
}

TEST_F(mark_entity_test, ul_accecn_rewrite)
{
  uint16_t s_port = 8080;
  uint16_t c_port = 5001;

  // 1. Send DL TCP packets to establish flow with both ecn1 and ce packets
  mark_impl->set_forced_l4s_prob(1.0);
  auto dl_pkt1 =
      make_ipv4_tcp(ip::ecn_codepoint::ect_1, server_ip, ue_ip, s_port, c_port, false, true, 1000, 1, 0, 0, 1336);
  mark->get_mark_tx_sdu_handler().handle_sdu(byte_buffer::create(dl_pkt1).value(), qos_flow_id_t::min);

  mark_impl->set_forced_l4s_prob(0.0);
  auto dl_pkt2 =
      make_ipv4_tcp(ip::ecn_codepoint::ect_1, server_ip, ue_ip, s_port, c_port, false, true, 2336, 1, 0, 0, 1336);
  mark->get_mark_tx_sdu_handler().handle_sdu(byte_buffer::create(dl_pkt2).value(), qos_flow_id_t::min);

  ASSERT_EQ(tx_notifier.received_pdus.size(), 2u);

  // 2. Send UL TCP ACK with AccECN option
  // Client -> Server: src = ue_ip, dst = server_ip, src_port = c_port, dst_port = s_port
  auto ul_ack = make_ipv4_tcp(
      ip::ecn_codepoint::ect_1, ue_ip, server_ip, c_port, s_port, false, true, 1, 3672, ip::TCP_OPT_ACCECN0, 11, 0);

  mark->get_mark_rx_pdu_handler().handle_pdu(byte_buffer::create(ul_ack).value(), qos_flow_id_t::min);

  ASSERT_EQ(rx_notifier.received_sdus.size(), 1u);
  auto item = std::move(rx_notifier.received_sdus.front());
  rx_notifier.received_sdus.pop();

  auto parsed = ip::parse_packet(item.sdu);
  EXPECT_TRUE(parsed.is_valid);
  EXPECT_TRUE(parsed.is_tcp);
  EXPECT_TRUE(parsed.tcp_ack);
  EXPECT_EQ(item.sdu[parsed.ihl_bytes + 20], ip::TCP_OPT_ACCECN0);

  // Checksum must be valid after rewrite
  uint16_t csum      = ip::compute_tcp_checksum(item.sdu, 0, parsed.ihl_bytes, item.sdu.length() - parsed.ihl_bytes);
  uint16_t wire_csum = (static_cast<uint16_t>(item.sdu[parsed.ihl_bytes + 16]) << 8) | item.sdu[parsed.ihl_bytes + 17];
  EXPECT_EQ(wire_csum, csum);
}

TEST_F(mark_entity_test, unmapped_qfi_is_not_accounted_or_marked)
{
  mark_impl->set_forced_l4s_prob(1.0);
  auto        raw_pkt = make_ipv4_udp(ip::ecn_codepoint::ect_1, 64);
  byte_buffer sdu     = byte_buffer::create(raw_pkt).value();

  // SDAP drops SDUs of unmapped QoS flows, so MARK must neither count them in a DRB queue nor mark them.
  qos_flow_id_t unmapped_qfi = uint_to_qos_flow_id(5);
  mark->get_mark_tx_sdu_handler().handle_sdu(std::move(sdu), unmapped_qfi);

  ASSERT_EQ(tx_notifier.received_pdus.size(), 1u);
  EXPECT_EQ(tx_notifier.received_pdus.front().pdu, raw_pkt);
  EXPECT_EQ(mark_impl->get_queue_model(drb_id_t::drb1)->get_next_sdu_sn(), 0u);
  EXPECT_EQ(mark_impl->get_flow_table().size(), 0u);
}

TEST(mark_flow_table_test, ack_base_survives_sequence_number_wrap)
{
  mark_flow_table           table;
  ip::five_tuple            dl_tuple{0x0a000001, 0x0a000002, 5201, 40000, 6};
  std::chrono::microseconds t{1000};
  table.map_flow(dl_tuple, drb_id_t::drb1, t, 5);

  // First ACK sets the base. A later ACK that wrapped past 2^32 must not be taken as an older ACK.
  auto first = table.get_and_update_ack(dl_tuple, 0xfffff000, t);
  ASSERT_TRUE(first.has_value());
  EXPECT_EQ(first->ack_raw, 0xfffff000U - 1);

  auto wrapped = table.get_and_update_ack(dl_tuple, 0x00000100, t);
  ASSERT_TRUE(wrapped.has_value());
  EXPECT_EQ(wrapped->ack_raw, 0xfffff000U - 1);
  EXPECT_EQ(static_cast<uint32_t>(0x00000100U - wrapped->ack_raw), 0x1101U);

  // A genuinely older ACK (reordering at flow start) still lowers the base.
  auto older = table.get_and_update_ack(dl_tuple, 0xffffe000, t);
  EXPECT_EQ(older->ack_raw, 0xffffe000U - 1);
}

TEST_F(mark_entity_test, dl_classic_tcp_is_ce_marked)
{
  mark_impl->set_forced_classic_prob(1.0);
  auto raw_pkt =
      make_ipv4_tcp(ip::ecn_codepoint::ect_0, 0x0a000001, 0x0a000002, 8080, 5001, false, true, 1000, 1, 0, 0, 100);
  mark->get_mark_tx_sdu_handler().handle_sdu(byte_buffer::create(raw_pkt).value(), qos_flow_id_t::min);

  ASSERT_EQ(tx_notifier.received_pdus.size(), 1u);
  auto item = std::move(tx_notifier.received_pdus.front());
  tx_notifier.received_pdus.pop();

  // Classic TCP is CE-marked on the wire, with a valid IP checksum, and is not counted as a virtual CE.
  auto parsed = ip::parse_packet(item.pdu);
  ASSERT_TRUE(parsed.is_valid);
  EXPECT_EQ(parsed.ecn, ip::ecn_codepoint::ce);
  EXPECT_EQ(parsed.ip_check, ip::compute_ip_checksum(item.pdu, 0, parsed.ihl_bytes));
  EXPECT_FALSE(mark_impl->get_flow_table().get_flow(parsed.tuple).has_value());
}

TEST_F(mark_entity_test, dl_classic_tcp_not_marked_when_p0)
{
  mark_impl->set_forced_classic_prob(0.0);
  auto raw_pkt =
      make_ipv4_tcp(ip::ecn_codepoint::ect_0, 0x0a000001, 0x0a000002, 8080, 5001, false, true, 1000, 1, 0, 0, 100);
  mark->get_mark_tx_sdu_handler().handle_sdu(byte_buffer::create(raw_pkt).value(), qos_flow_id_t::min);

  ASSERT_EQ(tx_notifier.received_pdus.size(), 1u);
  EXPECT_EQ(tx_notifier.received_pdus.front().pdu, raw_pkt);
}

TEST_F(mark_entity_test, ul_classic_ack_is_not_rewritten)
{
  // Classic flow marked on the DL. Its ACKs must be left untouched, so the sender is not signalled twice.
  mark_impl->set_forced_classic_prob(1.0);
  for (uint32_t seq : {1000U, 2336U}) {
    auto dl_pkt =
        make_ipv4_tcp(ip::ecn_codepoint::ect_0, server_ip, ue_ip, 8080, 5001, false, true, seq, 1, 0, 0, 1336);
    mark->get_mark_tx_sdu_handler().handle_sdu(byte_buffer::create(dl_pkt).value(), qos_flow_id_t::min);
  }

  auto ul_ack = make_ipv4_tcp(
      ip::ecn_codepoint::ect_0, ue_ip, server_ip, 5001, 8080, false, true, 1, 3672, ip::TCP_OPT_ACCECN0, 11, 0);
  mark->get_mark_rx_pdu_handler().handle_pdu(byte_buffer::create(ul_ack).value(), qos_flow_id_t::min);

  ASSERT_EQ(rx_notifier.received_sdus.size(), 1u);
  EXPECT_EQ(rx_notifier.received_sdus.front().sdu, ul_ack);
}

TEST_F(mark_entity_test, classic_tcp_ack_rewrite)
{
  // classic.tcp = ack_rewrite is the original L4Span behaviour: the DL packet is left unmarked, a virtual CE is
  // counted, and it is reported through the UL AccECN rewrite.
  mark_config c = cfg;
  c.classic.tcp = mark_signal::ack_rewrite;
  recreate(c);

  mark_impl->set_forced_classic_prob(1.0);
  send_dl_tcp(ip::ecn_codepoint::ect_0, 1000);
  mark_impl->set_forced_classic_prob(0.0);
  send_dl_tcp(ip::ecn_codepoint::ect_0, 2336);

  ASSERT_EQ(tx_notifier.received_pdus.size(), 2u);
  EXPECT_EQ(ip::parse_packet(tx_notifier.received_pdus.front().pdu).ecn, ip::ecn_codepoint::ect_0);

  auto [ack, out] = send_ul_ack(ip::ecn_codepoint::ect_0);
  EXPECT_NE(out, ack);
}

TEST_F(mark_entity_test, not_ect_ack_of_ack_rewrite_flow_is_rewritten)
{
  // The flow's DL class decides whether its ACKs are rewritten, not the ACK's own ECN codepoint.
  mark_impl->set_forced_l4s_prob(1.0);
  send_dl_tcp(ip::ecn_codepoint::ect_1, 1000);
  mark_impl->set_forced_l4s_prob(0.0);
  send_dl_tcp(ip::ecn_codepoint::ect_1, 2336);

  auto [ack, out] = send_ul_ack(ip::ecn_codepoint::not_ect);
  EXPECT_NE(out, ack);

  auto     parsed    = ip::parse_packet(out);
  uint16_t csum      = ip::compute_tcp_checksum(out, 0, parsed.ihl_bytes, out.length() - parsed.ihl_bytes);
  uint16_t wire_csum = (static_cast<uint16_t>(out[parsed.ihl_bytes + 16]) << 8) | out[parsed.ihl_bytes + 17];
  EXPECT_EQ(wire_csum, csum);
}

TEST_F(mark_entity_test, l4s_tcp_dl_ce)
{
  mark_config c = cfg;
  c.l4s.tcp     = mark_signal::dl_ce;
  recreate(c);

  mark_impl->set_forced_l4s_prob(1.0);
  send_dl_tcp(ip::ecn_codepoint::ect_1, 1000);
  send_dl_tcp(ip::ecn_codepoint::ect_1, 2336);

  ASSERT_EQ(tx_notifier.received_pdus.size(), 2u);
  auto parsed = ip::parse_packet(tx_notifier.received_pdus.front().pdu);
  EXPECT_EQ(parsed.ecn, ip::ecn_codepoint::ce);
  EXPECT_EQ(parsed.ip_check, ip::compute_ip_checksum(tx_notifier.received_pdus.front().pdu, 0, parsed.ihl_bytes));

  // Its ACKs are left untouched.
  auto [ack, out] = send_ul_ack(ip::ecn_codepoint::ect_1);
  EXPECT_EQ(out, ack);
}

TEST_F(mark_entity_test, none_signalling_leaves_packets_untouched)
{
  mark_config c = cfg;
  c.l4s.tcp     = mark_signal::none;
  c.classic.udp = mark_signal::none;
  recreate(c);

  mark_impl->set_forced_l4s_prob(1.0);
  mark_impl->set_forced_classic_prob(1.0);

  auto udp = make_ipv4_udp(ip::ecn_codepoint::ect_0, 64);
  mark->get_mark_tx_sdu_handler().handle_sdu(byte_buffer::create(udp).value(), qos_flow_id_t::min);
  ASSERT_EQ(tx_notifier.received_pdus.size(), 1u);
  EXPECT_EQ(tx_notifier.received_pdus.front().pdu, udp);

  send_dl_tcp(ip::ecn_codepoint::ect_1, 1000);
  send_dl_tcp(ip::ecn_codepoint::ect_1, 2336);
  ASSERT_EQ(tx_notifier.received_pdus.size(), 3u);
  tx_notifier.received_pdus.pop();
  EXPECT_EQ(ip::parse_packet(tx_notifier.received_pdus.front().pdu).ecn, ip::ecn_codepoint::ect_1);

  auto [ack, out] = send_ul_ack(ip::ecn_codepoint::ect_1);
  EXPECT_EQ(out, ack);
}
