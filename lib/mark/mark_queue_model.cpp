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

#include "mark_queue_model.h"
#include "srsran/support/srsran_assert.h"
#include <algorithm>

namespace srsran {

namespace srs_cu_up {

mark_queue_model::mark_queue_model(uint8_t sn_size_, const mark_config& cfg_) :
  cfg(cfg_), sn_size(sn_size_), mod_size(1u << sn_size_), mask(mod_size - 1), half(mod_size >> 1), ring(mod_size)
{
  srsran_assert((mod_size & mask) == 0, "Ring buffer size must be a power of two");
}

uint32_t mark_queue_model::push_sdu(size_t sdu_size, std::chrono::microseconds now, ip::ecn_codepoint ecn, bool is_syn)
{
  uint32_t sn               = next_sdu_sn;
  next_sdu_sn               = (next_sdu_sn + 1) & mask;
  ring[sn].pdcp_sn          = sn;
  ring[sn].size             = sdu_size;
  ring[sn].ingress_time     = now;
  ring[sn].cal_dequeue_rate = 0.0;

  if (!is_syn) {
    if (ecn == ip::ecn_codepoint::ect_1) {
      has_l4s_flow  = true;
      l4s_last_seen = now;
    } else if (ecn == ip::ecn_codepoint::ect_0) {
      has_classic_flow  = true;
      classic_last_seen = now;
    } else if (ecn == ip::ecn_codepoint::ce) {
      // Packets already CE-marked
      has_l4s_flow  = true;
      l4s_last_seen = now;
    }
  }

  return sn;
}

bool mark_queue_model::process_delivery_status(const nru_dl_data_delivery_status& status,
                                               std::chrono::microseconds          now,
                                               uint32_t                           nof_ue)
{
  bool advanced = false;

  if (status.highest_retransmitted_pdcp_sn.has_value()) {
    uint32_t target_sn = status.highest_retransmitted_pdcp_sn.value();
    uint32_t next_id   = (target_sn + 1) & mask;
    uint32_t delta     = (next_id - next_tx_id) & mask;
    if (delta > 0 && delta < half) {
      advance_sn(target_sn, now);
      advanced = true;
    }
  }

  if (status.highest_transmitted_pdcp_sn.has_value()) {
    uint32_t target_sn = status.highest_transmitted_pdcp_sn.value();
    uint32_t next_id   = (target_sn + 1) & mask;
    uint32_t delta     = (next_id - next_tx_id) & mask;
    if (delta > 0 && delta < half) {
      advance_sn(target_sn, now);
      advanced = true;
    }
  }

  if (advanced) {
    make_mark_decision(nof_ue);
  }

  return advanced;
}

void mark_queue_model::advance_sn(uint32_t target_sn, std::chrono::microseconds now)
{
  uint32_t next_id = (target_sn + 1) & mask;
  uint32_t delta   = (next_id - next_tx_id) & mask;
  if (delta == 0 || delta >= half) {
    return;
  }

  // Detect drift beyond the ring tail (settled decision §6.2)
  uint32_t delta_ahead_of_tail = (next_id - next_sdu_sn) & mask;
  if (delta_ahead_of_tail > 0 && delta_ahead_of_tail < half) {
    // Feedback SN is ahead of our pushed SDUs. Resync head to tail.
    next_tx_id = next_sdu_sn;
    ++nof_resyncs;
    return;
  }

  double total_bytes = 0.0;
  for (uint32_t step = 0; step < delta; ++step) {
    uint32_t sn = (next_tx_id + step) & mask;
    total_bytes += static_cast<double>(ring[sn].size);
  }

  double elapsed_time = 0.0;
  if (last_tx_time.count() > 0 && now >= last_tx_time) {
    elapsed_time = static_cast<double>((now - last_tx_time).count());
  } else if (ring[next_tx_id].ingress_time.count() > 0 && now >= ring[next_tx_id].ingress_time) {
    elapsed_time = static_cast<double>((now - ring[next_tx_id].ingress_time).count());
  }

  double measured_rate = 0.0;
  if (elapsed_time >= static_cast<double>(cfg.estimator.min_rate_interval_us)) {
    measured_rate = (elapsed_time > 0.0) ? (total_bytes / elapsed_time) : 0.0;
  } else if (last_dequeue_rate > 0.0) {
    measured_rate = last_dequeue_rate;
  } else {
    measured_rate = (elapsed_time > 0.0) ? (total_bytes / elapsed_time) : 0.0;
  }

  last_dequeue_rate = measured_rate;
  last_tx_time      = now;

  for (uint32_t step = 0; step < delta; ++step) {
    uint32_t sn               = (next_tx_id + step) & mask;
    ring[sn].transmitted_time = now;
    ring[sn].cal_dequeue_rate = measured_rate;
  }

  next_tx_id = next_id;
  nof_transmitted += delta;
}

void mark_queue_model::make_mark_decision(uint32_t nof_ue)
{
  // 1. Moving average and standard deviation of dequeue rate over last K transmitted packets
  size_t K = std::min(static_cast<size_t>(cfg.estimator.window_pkts), nof_transmitted);
  if (K == 0) {
    pred_rate  = 0.0;
    pred_error = 0.0;
  } else {
    double sum = 0.0;
    for (size_t k = 0; k < K; ++k) {
      uint32_t sn = (next_tx_id - 1 - k) & mask;
      sum += ring[sn].cal_dequeue_rate;
    }
    pred_rate = sum / static_cast<double>(K);

    double sq_sum = 0.0;
    for (size_t k = 0; k < K; ++k) {
      uint32_t sn   = (next_tx_id - 1 - k) & mask;
      double   diff = ring[sn].cal_dequeue_rate - pred_rate;
      sq_sum += diff * diff;
    }
    pred_error = std::sqrt(sq_sum / static_cast<double>(K));
  }

  // 2. Standing queue size and estimated queuing delay
  uint32_t standing_count = (next_sdu_sn - next_tx_id) & mask;
  standing_q_bytes        = 0.0;
  for (uint32_t step = 0; step < standing_count; ++step) {
    uint32_t sn = (next_tx_id + step) & mask;
    standing_q_bytes += static_cast<double>(ring[sn].size);
  }
  est_qdelay_us = (pred_rate > 0.0) ? (standing_q_bytes / pred_rate) : 0.0;

  // 3. L4S marking probability
  double l4s_target    = (cfg.l4s.target_delay_us > 0) ? static_cast<double>(cfg.l4s.target_delay_us) : 10000.0;
  double required_rate = standing_q_bytes / l4s_target;
  if (required_rate > pred_rate + pred_error) {
    raw_p_l4s = 1.0;
  } else if (required_rate < pred_rate - pred_error) {
    raw_p_l4s = 0.0;
  } else if (pred_error <= 1e-9) {
    raw_p_l4s = (required_rate >= pred_rate) ? 1.0 : 0.0;
  } else if (cfg.l4s.legacy_prob_truncation) {
    // Reproduces l4span/main exactly: the difference is cast to an unsigned integer and integer-divided by 2 before
    // the division by the prediction error.
    uint32_t num = static_cast<uint32_t>(required_rate - pred_rate + pred_error) / 2U;
    raw_p_l4s    = std::clamp(static_cast<double>(num) / pred_error, 0.0, 1.0);
  } else {
    raw_p_l4s = std::clamp((required_rate - pred_rate + pred_error) / (2.0 * pred_error), 0.0, 1.0);
  }

  // 4. Classic marking probability
  uint32_t classic_thres = cfg.classic.max_queue_bytes / std::max(1u, nof_ue);
  if (standing_q_bytes > static_cast<double>(classic_thres) && pred_rate > 0.0 && est_qdelay_us > 0.0) {
    double term =
        (static_cast<double>(cfg.classic.mss_bytes) * 8.0 * cfg.classic.beta / 2.0) / pred_rate / est_qdelay_us;
    raw_p_classic = std::clamp(term * term, 0.0, 1.0);
  } else {
    raw_p_classic = 0.0;
  }
}

bool mark_queue_model::have_l4s(std::chrono::microseconds now) const
{
  if (!has_l4s_flow) {
    return false;
  }
  auto timeout = std::chrono::milliseconds(cfg.flow_idle_timeout_ms);
  return (now - l4s_last_seen) <= timeout;
}

bool mark_queue_model::have_classic(std::chrono::microseconds now) const
{
  if (!has_classic_flow) {
    return false;
  }
  auto timeout = std::chrono::milliseconds(cfg.flow_idle_timeout_ms);
  return (now - classic_last_seen) <= timeout;
}

double mark_queue_model::get_p_l4s(std::chrono::microseconds now) const
{
  if (!have_l4s(now)) {
    return 0.0;
  }
  return raw_p_l4s;
}

double mark_queue_model::get_p_classic(std::chrono::microseconds now) const
{
  if (!have_classic(now)) {
    return 0.0;
  }
  return raw_p_classic;
}

} // namespace srs_cu_up

} // namespace srsran
