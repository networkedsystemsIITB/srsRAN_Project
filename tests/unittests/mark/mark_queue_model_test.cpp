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

#include "lib/mark/mark_queue_model.h"
#include <gtest/gtest.h>

using namespace srsran;
using namespace srs_cu_up;

namespace {

nru_dl_data_delivery_status make_tx_status(uint32_t highest_tx_sn)
{
  nru_dl_data_delivery_status status{};
  status.highest_transmitted_pdcp_sn = highest_tx_sn;
  return status;
}

} // namespace

TEST(mark_queue_model_test, basic_arrival_and_feedback)
{
  mark_config cfg;
  cfg.l4s_target_delay_us = 10000;
  mark_queue_model model(12, cfg);

  std::chrono::microseconds t0{100000};
  // Push 10 packets of 1000 bytes each
  for (int i = 0; i < 10; ++i) {
    model.push_sdu(1000, t0, ip::ecn_codepoint::ect_1, false);
  }

  EXPECT_EQ(model.get_next_sdu_sn(), 10u);
  EXPECT_EQ(model.get_next_tx_id(), 0u);
  EXPECT_TRUE(model.have_l4s(t0));
  EXPECT_FALSE(model.have_classic(t0));

  // Feedback acknowledging SN 0..4 (5 packets, 5000 bytes) at t0 + 10000 us
  std::chrono::microseconds t1      = t0 + std::chrono::microseconds(10000);
  bool                      updated = model.process_delivery_status(make_tx_status(4), t1, 1);
  EXPECT_TRUE(updated);
  EXPECT_EQ(model.get_next_tx_id(), 5u);
  EXPECT_EQ(model.get_nof_transmitted(), 5u);
  EXPECT_EQ(model.get_standing_queue_bytes(), 5000.0);

  // Rate: 5000 bytes / 10000 us = 0.5 bytes/us
  EXPECT_NEAR(model.get_pred_rate(), 0.5, 1e-6);
  EXPECT_NEAR(model.get_pred_error(), 0.0, 1e-6);
  EXPECT_NEAR(model.get_est_qdelay_us(), 10000.0, 1e-6); // 5000 / 0.5 = 10000 us

  // Required rate = 5000 / 10000 = 0.5 bytes/us. Since required == pred and err == 0:
  EXPECT_NEAR(model.get_p_l4s(t1), 1.0, 1e-6);
}

TEST(mark_queue_model_test, zero_error_handling)
{
  mark_config cfg;
  cfg.l4s_target_delay_us = 10000;
  mark_queue_model model(12, cfg);

  std::chrono::microseconds t{100000};
  for (int i = 0; i < 20; ++i) {
    model.push_sdu(1000, t, ip::ecn_codepoint::ect_1, false);
  }

  // Dequeue first 10 packets with uniform rate 1.0 bytes/us (10000 bytes / 10000 us)
  t += std::chrono::microseconds(10000);
  model.process_delivery_status(make_tx_status(9), t, 1);

  EXPECT_NEAR(model.get_pred_rate(), 1.0, 1e-6);
  EXPECT_NEAR(model.get_pred_error(), 0.0, 1e-6);

  // Remaining standing queue is 10000 bytes. Required rate = 10000 / 10000 = 1.0 bytes/us.
  // required == pred, err == 0 => p = 1.0
  EXPECT_EQ(model.get_p_l4s(t), 1.0);

  // Add 1 more packet: standing queue = 11000 bytes. Required rate = 1.1 > pred => p = 1.0
  model.push_sdu(1000, t, ip::ecn_codepoint::ect_1, false);
  model.make_mark_decision(1);
  EXPECT_EQ(model.get_p_l4s(t), 1.0);
}

TEST(mark_queue_model_test, sn_wrap_around_12bit)
{
  mark_config      cfg;
  mark_queue_model model(12, cfg); // 4096 SN space

  std::chrono::microseconds t{1000000};

  // Push and advance up to SN 4090
  for (uint32_t i = 0; i < 4090; ++i) {
    model.push_sdu(100, t, ip::ecn_codepoint::ect_1, false);
  }
  // Advance in chunks to stay within half-ring delta
  for (uint32_t f = 999; f < 4090; f += 1000) {
    t += std::chrono::microseconds(10000);
    model.process_delivery_status(make_tx_status(f), t, 1);
  }
  t += std::chrono::microseconds(10000);
  model.process_delivery_status(make_tx_status(4089), t, 1);
  EXPECT_EQ(model.get_next_tx_id(), 4090u);

  // Now push 20 packets spanning across wrap boundary (4090..4095, 0..13)
  for (int i = 0; i < 20; ++i) {
    model.push_sdu(500, t, ip::ecn_codepoint::ect_1, false);
  }
  EXPECT_EQ(model.get_next_sdu_sn(), 14u); // wrapped past 4095 to 14
  model.make_mark_decision(1);
  EXPECT_EQ(model.get_standing_queue_bytes(), 20 * 500.0);

  // Acknowledge up to SN 5 (spanning 4090..4095 and 0..5 = 12 packets)
  t += std::chrono::microseconds(10000);
  model.process_delivery_status(make_tx_status(5), t, 1);

  EXPECT_EQ(model.get_next_tx_id(), 6u);
  EXPECT_EQ(model.get_standing_queue_bytes(), 8 * 500.0); // 8 packets remaining (6..13)
  EXPECT_TRUE(model.get_pred_rate() > 0.0);
}

TEST(mark_queue_model_test, sn_wrap_around_18bit)
{
  mark_config      cfg;
  mark_queue_model model(18, cfg); // 262144 SN space

  std::chrono::microseconds t{1000000};

  // Push packets near 262140
  // Simulate fast-forwarding to 262140
  for (uint32_t i = 0; i < 100; ++i) {
    model.push_sdu(200, t, ip::ecn_codepoint::ect_1, false);
  }
  t += std::chrono::microseconds(10000);
  model.process_delivery_status(make_tx_status(99), t, 1);
  EXPECT_EQ(model.get_next_tx_id(), 100u);
  EXPECT_EQ(model.get_standing_queue_bytes(), 0.0);
}

TEST(mark_queue_model_test, golden_l4s_probability_comparison)
{
  // Test linear region: required_rate between pred - err and pred + err
  mark_config cfg_normal;
  cfg_normal.l4s_target_delay_us        = 10000;
  cfg_normal.legacy_l4s_prob_truncation = false;
  cfg_normal.pred_window_pkts           = 4;
  mark_queue_model model_normal(12, cfg_normal);

  mark_config cfg_legacy;
  cfg_legacy.l4s_target_delay_us        = 10000;
  cfg_legacy.legacy_l4s_prob_truncation = true;
  cfg_legacy.pred_window_pkts           = 4;
  mark_queue_model model_legacy(12, cfg_legacy);

  std::chrono::microseconds t{100000};

  // Feed both models identical arrivals: 10 packets of 1000 bytes
  for (int i = 0; i < 10; ++i) {
    model_normal.push_sdu(1000, t, ip::ecn_codepoint::ect_1, false);
    model_legacy.push_sdu(1000, t, ip::ecn_codepoint::ect_1, false);
  }

  // Two feedback steps with different rates to create non-zero standard deviation:
  // Step 1: 2 packets (2000 bytes) in 5000 us => rate = 0.4 bytes/us
  t += std::chrono::microseconds(5000);
  model_normal.process_delivery_status(make_tx_status(1), t, 1);
  model_legacy.process_delivery_status(make_tx_status(1), t, 1);

  // Step 2: 2 packets (2000 bytes) in 2500 us => rate = 0.8 bytes/us
  t += std::chrono::microseconds(2500);
  model_normal.process_delivery_status(make_tx_status(3), t, 1);
  model_legacy.process_delivery_status(make_tx_status(3), t, 1);

  // Window of 2 packets has rates 0.4 and 0.8:
  // pred_rate = (0.4 + 0.8) / 2 = 0.6 bytes/us
  // pred_error = sqrt( ((0.4-0.6)^2 + (0.8-0.6)^2) / 2 ) = sqrt(0.04) = 0.2 bytes/us
  EXPECT_NEAR(model_normal.get_pred_rate(), 0.6, 1e-5);
  EXPECT_NEAR(model_normal.get_pred_error(), 0.2, 1e-5);

  // Standing queue is 6 packets = 6000 bytes.
  // required_rate = 6000 / 10000 = 0.6 bytes/us.
  // required (0.6) == pred (0.6), so p_l4s = (0.6 - 0.6 + 0.2) / (2 * 0.2) = 0.2 / 0.4 = 0.5!
  EXPECT_NEAR(model_normal.get_p_l4s(t), 0.5, 1e-4);

  // In legacy formula: (uint32_t)(req - pred + err) = (uint32_t)(0.6 - 0.6 + 0.2) = (uint32_t)(0.2) = 0!
  // So legacy formula produces 0.0!
  EXPECT_EQ(model_legacy.get_p_l4s(t), 0.0);
}

TEST(mark_queue_model_test, classic_probability)
{
  mark_config cfg;
  cfg.classic_max_queue_bytes = 20000;
  cfg.classic_mss_bytes       = 1460;
  cfg.classic_beta            = 1.75;
  mark_queue_model model(12, cfg);

  std::chrono::microseconds t{100000};
  // Push 30 packets of 1000 bytes = 30000 bytes
  for (int i = 0; i < 30; ++i) {
    model.push_sdu(1000, t, ip::ecn_codepoint::ect_0, false);
  }

  // Dequeue 5 packets in 5000 us => rate = 1.0 bytes/us
  t += std::chrono::microseconds(5000);
  model.process_delivery_status(make_tx_status(4), t, 1);

  // Standing queue is 25000 bytes > classic_max_queue_bytes (20000).
  EXPECT_TRUE(model.have_classic(t));
  EXPECT_GT(model.get_p_classic(t), 0.0);

  // est_qdelay = 25000 / 1.0 = 25000 us.
  // expected term = 1460 * 8 * 1.75 / 2 / 1.0 / 25000 = 10220 / 25000 = 0.4088
  // p_classic = 0.4088^2 = 0.1671
  double expected_term = (1460.0 * 8.0 * 1.75 / 2.0) / 1.0 / 25000.0;
  EXPECT_NEAR(model.get_p_classic(t), expected_term * expected_term, 1e-4);
}

TEST(mark_queue_model_test, drift_detection_beyond_tail)
{
  mark_config      cfg;
  mark_queue_model model(12, cfg);

  std::chrono::microseconds t{100000};
  // Push 5 packets (SN 0..4)
  for (int i = 0; i < 5; ++i) {
    model.push_sdu(1000, t, ip::ecn_codepoint::ect_1, false);
  }
  EXPECT_EQ(model.get_next_sdu_sn(), 5u);

  // Feedback reports SN 50 (far beyond our tail of 5)
  t += std::chrono::microseconds(5000);
  model.process_delivery_status(make_tx_status(50), t, 1);

  // Head should be resynced to tail (5)
  EXPECT_EQ(model.get_next_tx_id(), 5u);
  EXPECT_EQ(model.get_standing_queue_bytes(), 0.0);
}

TEST(mark_queue_model_test, legacy_truncation_is_bit_exact_with_l4span)
{
  // Rates 2 and 6 B/us over 4 packets give pred_rate = 4 and pred_error = 2. A standing queue of 50000 B with a
  // 10000 us target requires 5 B/us, so req - pred + err = 3.
  // l4span/main: (uint32_t)(3) / 2 = 1 (integer division), 1 / 2 = 0.5. Intended formula: 3 / (2 * 2) = 0.75.
  auto run = [](bool legacy) {
    mark_config cfg;
    cfg.l4s_target_delay_us        = 10000;
    cfg.pred_window_pkts           = 4;
    cfg.legacy_l4s_prob_truncation = legacy;
    mark_queue_model model(12, cfg);

    std::chrono::microseconds t{100000};
    for (size_t sz : {1000, 1000, 3000, 3000}) {
      model.push_sdu(sz, t, ip::ecn_codepoint::ect_1, false);
    }
    for (int i = 0; i < 50; ++i) {
      model.push_sdu(1000, t, ip::ecn_codepoint::ect_1, false);
    }
    t += std::chrono::microseconds(1000);
    model.process_delivery_status(make_tx_status(1), t, 1); // 2000 B / 1000 us = 2 B/us
    t += std::chrono::microseconds(1000);
    model.process_delivery_status(make_tx_status(3), t, 1); // 6000 B / 1000 us = 6 B/us

    EXPECT_NEAR(model.get_pred_rate(), 4.0, 1e-9);
    EXPECT_NEAR(model.get_pred_error(), 2.0, 1e-9);
    EXPECT_NEAR(model.get_standing_queue_bytes(), 50000.0, 1e-9);
    return model.get_p_l4s(t);
  };

  EXPECT_NEAR(run(true), 0.5, 1e-9);
  EXPECT_NEAR(run(false), 0.75, 1e-9);
}

// The following cases are adapted from the RingBuffer tests proposed in PrincetonUniversity/L4Span#2. The 24.10
// RingBuffer class no longer exists; the ring is internal to mark_queue_model and is exercised through its API.

TEST(mark_queue_model_test, sns_are_assigned_in_push_order)
{
  mark_config      cfg;
  mark_queue_model model(12, cfg);

  std::chrono::microseconds t{100000};
  for (uint32_t i = 0; i < 10; ++i) {
    EXPECT_EQ(model.push_sdu(100 + i, t, ip::ecn_codepoint::ect_1, false), i);
  }
  EXPECT_EQ(model.get_next_sdu_sn(), 10U);

  // Standing queue is the sum of the sizes stored in each SN slot.
  model.make_mark_decision(1);
  EXPECT_NEAR(model.get_standing_queue_bytes(), 1045.0, 1e-9);
}

TEST(mark_queue_model_test, sn_wraps_modulo_12bit_sn_space)
{
  mark_config      cfg;
  mark_queue_model model(12, cfg);

  std::chrono::microseconds t{100000};
  for (uint32_t i = 0; i < 4096; ++i) {
    model.push_sdu(100, t, ip::ecn_codepoint::ect_1, false);
  }
  EXPECT_EQ(model.get_next_sdu_sn(), 0U);
  EXPECT_EQ(model.push_sdu(100, t, ip::ecn_codepoint::ect_1, false), 0U);
}

TEST(mark_queue_model_test, all_12bit_slots_are_distinct)
{
  mark_config      cfg;
  mark_queue_model model(12, cfg);

  // 4095 is the largest standing queue representable in a 4096 SN space. If two SNs aliased the same slot, the
  // standing queue would not equal the sum of all pushed sizes.
  std::chrono::microseconds t{100000};
  double                    expected = 0;
  for (uint32_t i = 0; i < 4095; ++i) {
    model.push_sdu(i + 1, t, ip::ecn_codepoint::ect_1, false);
    expected += i + 1;
  }
  model.make_mark_decision(1);
  EXPECT_NEAR(model.get_standing_queue_bytes(), expected, 1e-9);
}

TEST(mark_queue_model_test, wrapped_sn_overwrites_old_slot)
{
  mark_config      cfg;
  mark_queue_model model(12, cfg);

  std::chrono::microseconds t{100000};
  for (uint32_t i = 0; i < 4095; ++i) {
    model.push_sdu(100, t, ip::ecn_codepoint::ect_1, false);
  }
  // Drain SNs 0..4094 in chunks smaller than half the SN space.
  for (uint32_t sn = 999; sn < 4095; sn += 1000) {
    t += std::chrono::microseconds(10000);
    model.process_delivery_status(make_tx_status(sn), t, 1);
  }
  t += std::chrono::microseconds(10000);
  model.process_delivery_status(make_tx_status(4094), t, 1);
  ASSERT_EQ(model.get_next_tx_id(), 4095U);

  // SN 4095 and then SN 0 (wrapped). Slot 0 previously held 100 B and must now hold 222 B.
  EXPECT_EQ(model.push_sdu(111, t, ip::ecn_codepoint::ect_1, false), 4095U);
  EXPECT_EQ(model.push_sdu(222, t, ip::ecn_codepoint::ect_1, false), 0U);
  model.make_mark_decision(1);
  EXPECT_NEAR(model.get_standing_queue_bytes(), 333.0, 1e-9);
}

TEST(mark_queue_model_test, sns_do_not_alias_in_18bit_sn_space)
{
  mark_config      cfg;
  mark_queue_model model(18, cfg);

  std::chrono::microseconds t{100000};
  for (uint32_t i = 0; i < 4096; ++i) {
    model.push_sdu(1, t, ip::ecn_codepoint::ect_1, false);
  }
  // SN 4096 is a distinct slot in an 18-bit SN space (it would alias SN 0 with 12 bits).
  EXPECT_EQ(model.push_sdu(10, t, ip::ecn_codepoint::ect_1, false), 4096U);
  model.make_mark_decision(1);
  EXPECT_NEAR(model.get_standing_queue_bytes(), 4096.0 + 10.0, 1e-9);
}
