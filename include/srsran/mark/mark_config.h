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

#pragma once

#include "fmt/format.h"
#include <cstdint>

namespace srsran {

struct mark_config {
  bool     enabled                    = false;
  uint32_t l4s_target_delay_us        = 10000;
  uint32_t classic_max_queue_bytes    = 225000;
  uint32_t pred_window_pkts           = 50;
  uint32_t min_rate_interval_us       = 1000;
  uint32_t flow_idle_timeout_ms       = 1000;
  bool     dl_udp_mark                = true;
  bool     ul_ack_rewrite             = true;
  uint32_t ack_mss_bytes              = 1336;
  double   l4s_ce_portion_scale       = 0.1;
  uint32_t ce_pkt_offset              = 5;
  uint32_t classic_mss_bytes          = 1460;
  double   classic_beta               = 1.75;
  bool     legacy_l4s_prob_truncation = false;
};

} // namespace srsran

namespace fmt {

template <>
struct formatter<srsran::mark_config> {
  template <typename ParseContext>
  auto parse(ParseContext& ctx) -> decltype(ctx.begin())
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto format(const srsran::mark_config& cfg, FormatContext& ctx) const -> decltype(std::declval<FormatContext>().out())
  {
    return format_to(ctx.out(),
                     "enabled={} l4s_target_delay_us={} classic_max_queue_bytes={} pred_window_pkts={} "
                     "min_rate_interval_us={} flow_idle_timeout_ms={} dl_udp_mark={} ul_ack_rewrite={} "
                     "ack_mss_bytes={} l4s_ce_portion_scale={} ce_pkt_offset={} classic_mss_bytes={} "
                     "classic_beta={} legacy_l4s_prob_truncation={}",
                     cfg.enabled,
                     cfg.l4s_target_delay_us,
                     cfg.classic_max_queue_bytes,
                     cfg.pred_window_pkts,
                     cfg.min_rate_interval_us,
                     cfg.flow_idle_timeout_ms,
                     cfg.dl_udp_mark,
                     cfg.ul_ack_rewrite,
                     cfg.ack_mss_bytes,
                     cfg.l4s_ce_portion_scale,
                     cfg.ce_pkt_offset,
                     cfg.classic_mss_bytes,
                     cfg.classic_beta,
                     cfg.legacy_l4s_prob_truncation);
  }
};

} // namespace fmt
