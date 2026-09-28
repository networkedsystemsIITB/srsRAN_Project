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

#include "ip_utils.h"
#include "srsran/mark/mark_config.h"
#include "srsran/nru/nru_message.h"
#include "srsran/ran/rb_id.h"
#include <chrono>
#include <cmath>
#include <vector>

namespace srsran {

namespace srs_cu_up {

struct packet_record {
  uint32_t                  pdcp_sn          = 0;
  size_t                    size             = 0;
  std::chrono::microseconds ingress_time     = {};
  std::chrono::microseconds transmitted_time = {};
  double                    cal_dequeue_rate = 0.0;
};

class mark_queue_model
{
public:
  explicit mark_queue_model(uint8_t sn_size, const mark_config& cfg);

  /// Pushes an incoming DL SDU into the shadow queue model.
  /// Returns the assigned predicted PDCP sequence number.
  uint32_t push_sdu(size_t sdu_size, std::chrono::microseconds now, ip::ecn_codepoint ecn, bool is_syn);

  /// Processes DDDS feedback from the DU. Returns true if marking decision was updated.
  bool
  process_delivery_status(const nru_dl_data_delivery_status& status, std::chrono::microseconds now, uint32_t nof_ue);

  /// Explicitly recomputes the marking decision.
  void make_mark_decision(uint32_t nof_ue);

  // Flow liveness
  bool have_l4s(std::chrono::microseconds now) const;
  bool have_classic(std::chrono::microseconds now) const;

  // Marking probabilities
  double get_p_l4s(std::chrono::microseconds now) const;
  double get_p_classic(std::chrono::microseconds now) const;

  // Diagnostics and metrics
  double   get_pred_rate() const { return pred_rate; }
  double   get_pred_error() const { return pred_error; }
  double   get_standing_queue_bytes() const { return standing_q_bytes; }
  double   get_est_qdelay_us() const { return est_qdelay_us; }
  uint32_t get_next_tx_id() const { return next_tx_id; }
  uint32_t get_next_sdu_sn() const { return next_sdu_sn; }
  size_t   get_nof_transmitted() const { return nof_transmitted; }
  double   get_raw_p_l4s() const { return raw_p_l4s; }
  double   get_raw_p_classic() const { return raw_p_classic; }
  /// Number of times the model resynchronised its head to the tail because feedback ran ahead of the pushed SDUs.
  uint32_t get_nof_resyncs() const { return nof_resyncs; }

private:
  void advance_sn(uint32_t target_sn, std::chrono::microseconds now);

  const mark_config cfg;
  uint8_t           sn_size;
  uint32_t          mod_size;
  uint32_t          mask;
  uint32_t          half;

  std::vector<packet_record> ring;

  uint32_t next_sdu_sn     = 0;
  uint32_t next_tx_id      = 0;
  size_t   nof_transmitted = 0;
  uint32_t nof_resyncs     = 0;

  std::chrono::microseconds last_tx_time      = {};
  double                    last_dequeue_rate = 0.0;
  double                    pred_rate         = 0.0;
  double                    pred_error        = 0.0;
  double                    standing_q_bytes  = 0.0;
  double                    est_qdelay_us     = 0.0;
  double                    raw_p_l4s         = 0.0;
  double                    raw_p_classic     = 0.0;

  bool                      has_l4s_flow      = false;
  bool                      has_classic_flow  = false;
  std::chrono::microseconds l4s_last_seen     = {};
  std::chrono::microseconds classic_last_seen = {};
};

} // namespace srs_cu_up

} // namespace srsran
