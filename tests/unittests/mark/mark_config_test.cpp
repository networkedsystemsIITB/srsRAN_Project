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

#include "apps/units/o_cu_up/cu_up/cu_up_unit_config.h"
#include "apps/units/o_cu_up/cu_up/cu_up_unit_config_cli11_schema.h"
#include "apps/units/o_cu_up/cu_up/cu_up_unit_config_translators.h"
#include "apps/units/o_cu_up/cu_up/cu_up_unit_config_yaml_writer.h"
#include "srsran/mark/mark_config.h"
#include "srsran/support/config_parsers.h"
#include <gtest/gtest.h>
#include <sstream>

using namespace srsran;

TEST(mark_config_test, format_string)
{
  mark_config cfg;
  cfg.enabled             = true;
  cfg.l4s_target_delay_us = 12345;
  std::string s           = fmt::format("{}", cfg);
  EXPECT_TRUE(s.find("enabled=true") != std::string::npos);
  EXPECT_TRUE(s.find("l4s_target_delay_us=12345") != std::string::npos);
}

TEST(mark_config_test, yaml_write_and_cli11_roundtrip)
{
  cu_up_unit_config orig_cfg;
  orig_cfg.loggers.mark_level                    = srslog::basic_levels::debug;
  orig_cfg.l4span_cfg.enabled                    = true;
  orig_cfg.l4span_cfg.l4s_target_delay_us        = 8000;
  orig_cfg.l4span_cfg.classic_max_queue_bytes    = 150000;
  orig_cfg.l4span_cfg.pred_window_pkts           = 60;
  orig_cfg.l4span_cfg.min_rate_interval_us       = 2000;
  orig_cfg.l4span_cfg.flow_idle_timeout_ms       = 500;
  orig_cfg.l4span_cfg.dl_udp_mark                = false;
  orig_cfg.l4span_cfg.dl_classic_tcp_mark        = false;
  orig_cfg.l4span_cfg.ul_ack_rewrite             = false;
  orig_cfg.l4span_cfg.ack_mss_bytes              = 1400;
  orig_cfg.l4span_cfg.l4s_ce_portion_scale       = 0.2;
  orig_cfg.l4span_cfg.ce_pkt_offset              = 10;
  orig_cfg.l4span_cfg.classic_mss_bytes          = 1500;
  orig_cfg.l4span_cfg.classic_beta               = 2.0;
  orig_cfg.l4span_cfg.legacy_l4s_prob_truncation = true;

  // 1. Write to YAML
  YAML::Node node;
  fill_cu_up_config_in_yaml_schema(node, orig_cfg);

  ASSERT_TRUE(node["cu_up"]["l4span"].IsDefined());
  EXPECT_EQ(node["cu_up"]["l4span"]["enabled"].as<bool>(), true);
  EXPECT_EQ(node["cu_up"]["l4span"]["l4s_target_delay_us"].as<uint32_t>(), 8000);
  EXPECT_EQ(node["cu_up"]["l4span"]["classic_max_queue_bytes"].as<uint32_t>(), 150000);
  EXPECT_EQ(node["cu_up"]["l4span"]["pred_window_pkts"].as<uint32_t>(), 60);
  EXPECT_EQ(node["cu_up"]["l4span"]["min_rate_interval_us"].as<uint32_t>(), 2000);
  EXPECT_EQ(node["cu_up"]["l4span"]["flow_idle_timeout_ms"].as<uint32_t>(), 500);
  EXPECT_EQ(node["cu_up"]["l4span"]["dl_udp_mark"].as<bool>(), false);
  EXPECT_EQ(node["cu_up"]["l4span"]["dl_classic_tcp_mark"].as<bool>(), false);
  EXPECT_EQ(node["cu_up"]["l4span"]["ul_ack_rewrite"].as<bool>(), false);
  EXPECT_EQ(node["cu_up"]["l4span"]["ack_mss_bytes"].as<uint32_t>(), 1400);
  EXPECT_DOUBLE_EQ(node["cu_up"]["l4span"]["l4s_ce_portion_scale"].as<double>(), 0.2);
  EXPECT_EQ(node["cu_up"]["l4span"]["ce_pkt_offset"].as<uint32_t>(), 10);
  EXPECT_EQ(node["cu_up"]["l4span"]["classic_mss_bytes"].as<uint32_t>(), 1500);
  EXPECT_DOUBLE_EQ(node["cu_up"]["l4span"]["classic_beta"].as<double>(), 2.0);
  EXPECT_EQ(node["cu_up"]["l4span"]["legacy_l4s_prob_truncation"].as<bool>(), true);
  EXPECT_EQ(node["log"]["mark_level"].as<std::string>(), "debug");

  // 2. Dump YAML to string
  YAML::Emitter emitter;
  emitter << node;
  std::string yaml_str = emitter.c_str();

  // 3. Parse YAML back through CLI11 schema
  cu_up_unit_config parsed_cfg;
  CLI::App          app{"CU-UP test parser"};
  app.config_formatter(create_yaml_config_parser());
  app.set_config("--config");
  configure_cli11_with_cu_up_unit_config_schema(app, parsed_cfg);

  std::istringstream ss(yaml_str);
  app.parse_from_stream(ss);

  EXPECT_EQ(parsed_cfg.l4span_cfg.enabled, true);
  EXPECT_EQ(parsed_cfg.l4span_cfg.l4s_target_delay_us, 8000);
  EXPECT_EQ(parsed_cfg.l4span_cfg.classic_max_queue_bytes, 150000);
  EXPECT_EQ(parsed_cfg.l4span_cfg.pred_window_pkts, 60);
  EXPECT_EQ(parsed_cfg.l4span_cfg.min_rate_interval_us, 2000);
  EXPECT_EQ(parsed_cfg.l4span_cfg.flow_idle_timeout_ms, 500);
  EXPECT_EQ(parsed_cfg.l4span_cfg.dl_udp_mark, false);
  EXPECT_EQ(parsed_cfg.l4span_cfg.dl_classic_tcp_mark, false);
  EXPECT_EQ(parsed_cfg.l4span_cfg.ul_ack_rewrite, false);
  EXPECT_EQ(parsed_cfg.l4span_cfg.ack_mss_bytes, 1400);
  EXPECT_DOUBLE_EQ(parsed_cfg.l4span_cfg.l4s_ce_portion_scale, 0.2);
  EXPECT_EQ(parsed_cfg.l4span_cfg.ce_pkt_offset, 10);
  EXPECT_EQ(parsed_cfg.l4span_cfg.classic_mss_bytes, 1500);
  EXPECT_DOUBLE_EQ(parsed_cfg.l4span_cfg.classic_beta, 2.0);
  EXPECT_EQ(parsed_cfg.l4span_cfg.legacy_l4s_prob_truncation, true);
  EXPECT_EQ(parsed_cfg.loggers.mark_level, srslog::basic_levels::debug);

  // 4. Translate to cu_up_config
  srs_cu_up::cu_up_config cu_up_cfg = generate_cu_up_config(parsed_cfg);
  EXPECT_EQ(cu_up_cfg.mark.enabled, true);
  EXPECT_EQ(cu_up_cfg.mark.l4s_target_delay_us, 8000);
  EXPECT_EQ(cu_up_cfg.mark.classic_max_queue_bytes, 150000);
  EXPECT_EQ(cu_up_cfg.mark.pred_window_pkts, 60);
  EXPECT_EQ(cu_up_cfg.mark.min_rate_interval_us, 2000);
  EXPECT_EQ(cu_up_cfg.mark.flow_idle_timeout_ms, 500);
  EXPECT_EQ(cu_up_cfg.mark.dl_udp_mark, false);
  EXPECT_EQ(cu_up_cfg.mark.dl_classic_tcp_mark, false);
  EXPECT_EQ(cu_up_cfg.mark.ul_ack_rewrite, false);
  EXPECT_EQ(cu_up_cfg.mark.ack_mss_bytes, 1400);
  EXPECT_DOUBLE_EQ(cu_up_cfg.mark.l4s_ce_portion_scale, 0.2);
  EXPECT_EQ(cu_up_cfg.mark.ce_pkt_offset, 10);
  EXPECT_EQ(cu_up_cfg.mark.classic_mss_bytes, 1500);
  EXPECT_DOUBLE_EQ(cu_up_cfg.mark.classic_beta, 2.0);
  EXPECT_EQ(cu_up_cfg.mark.legacy_l4s_prob_truncation, true);
}
