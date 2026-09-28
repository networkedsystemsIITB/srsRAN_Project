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

/// How congestion is signalled to the sender of a flow.
enum class mark_signal {
  /// No signalling. Marking probabilities are still computed and logged.
  none,
  /// CE-mark the DL packet. The receiver echoes it (RFC 3168 ECN or AccECN).
  dl_ce,
  /// Leave the DL packet unmarked and rewrite the AccECN feedback of the UL ACKs (TCP only).
  ack_rewrite,
};

inline const char* to_string(mark_signal signal)
{
  switch (signal) {
    case mark_signal::none:
      return "none";
    case mark_signal::dl_ce:
      return "dl_ce";
    case mark_signal::ack_rewrite:
      return "ack_rewrite";
  }
  return "invalid";
}

/// L4Span (MARK) configuration. Defaults equal the constants of the original L4Span implementation.
struct mark_config {
  /// Dequeue rate estimator of the per-DRB queue model.
  struct estimator_config {
    /// Moving-average window of the dequeue rate predictor, in packets.
    uint32_t window_pkts = 50;
    /// Reuse the previous dequeue rate if delivery status feedback arrives sooner than this.
    uint32_t min_rate_interval_us = 1000;
  };

  /// L4S (ECT(1)) flows.
  struct l4s_config {
    /// Target queueing delay.
    uint32_t target_delay_us = 10000;
    /// Reproduce the integer truncation of the marking probability in the original implementation.
    bool legacy_prob_truncation = false;
    /// Signalling of TCP flows.
    mark_signal tcp = mark_signal::ack_rewrite;
    /// Signalling of UDP flows (none or dl_ce).
    mark_signal udp = mark_signal::dl_ce;
  };

  /// Classic (ECT(0)) flows.
  struct classic_config {
    /// Standing queue above which classic flows are marked. Divided by the number of UEs.
    uint32_t max_queue_bytes = 225000;
    /// MSS used by the marking probability.
    uint32_t mss_bytes = 1460;
    /// Constant used by the marking probability.
    double beta = 1.75;
    /// Signalling of TCP flows.
    mark_signal tcp = mark_signal::dl_ce;
    /// Signalling of UDP flows (none or dl_ce).
    mark_signal udp = mark_signal::dl_ce;
  };

  /// Parameters of the UL AccECN feedback rewrite, used by the classes whose TCP signalling is ack_rewrite.
  struct ack_rewrite_config {
    /// Segment size assumed when synthesizing the AccECN counters.
    uint32_t mss_bytes = 1336;
    /// Initial CE packet counter offset.
    uint32_t ce_pkt_offset = 5;
    /// Scale of the CE portion reported to L4S flows.
    double l4s_ce_scale = 0.1;
  };

  bool     enabled              = false;
  uint32_t flow_idle_timeout_ms = 1000;

  estimator_config   estimator;
  l4s_config         l4s;
  classic_config     classic;
  ack_rewrite_config ack_rewrite;
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
                     "enabled={} flow_idle_timeout_ms={} estimator=[window_pkts={} min_rate_interval_us={}] "
                     "l4s=[target_delay_us={} legacy_prob_truncation={} tcp={} udp={}] "
                     "classic=[max_queue_bytes={} mss_bytes={} beta={} tcp={} udp={}] "
                     "ack_rewrite=[mss_bytes={} ce_pkt_offset={} l4s_ce_scale={}]",
                     cfg.enabled,
                     cfg.flow_idle_timeout_ms,
                     cfg.estimator.window_pkts,
                     cfg.estimator.min_rate_interval_us,
                     cfg.l4s.target_delay_us,
                     cfg.l4s.legacy_prob_truncation,
                     srsran::to_string(cfg.l4s.tcp),
                     srsran::to_string(cfg.l4s.udp),
                     cfg.classic.max_queue_bytes,
                     cfg.classic.mss_bytes,
                     cfg.classic.beta,
                     srsran::to_string(cfg.classic.tcp),
                     srsran::to_string(cfg.classic.udp),
                     cfg.ack_rewrite.mss_bytes,
                     cfg.ack_rewrite.ce_pkt_offset,
                     cfg.ack_rewrite.l4s_ce_scale);
  }
};

} // namespace fmt
