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

#include "mark_flow_table.h"
#include "mark_queue_model.h"
#include "mark_session_logger.h"
#include "srsran/mark/mark.h"
#include "srsran/mark/mark_config.h"
#include "srsran/mark/mark_factory.h"
#include "srsran/srslog/srslog.h"
#include <atomic>
#include <mutex>
#include <optional>
#include <random>
#include <unordered_map>

namespace srsran {

namespace srs_cu_up {

class mark_entity_impl : public mark_entity,
                         public mark_tx_sdu_handler,
                         public mark_rx_pdu_handler,
                         public mark_delivery_status_handler
{
public:
  mark_entity_impl(uint32_t                     ue_index,
                   pdu_session_id_t             psi,
                   mark_rx_sdu_notifier&        rx_sdu_notifier,
                   mark_tx_pdu_notifier&        tx_pdu_notifier,
                   const mark_config&           cfg,
                   const std::atomic<uint32_t>& nof_ues);

  ~mark_entity_impl() override = default;

  // mark_entity interfaces
  mark_rx_pdu_handler&          get_mark_rx_pdu_handler() override { return *this; }
  mark_tx_sdu_handler&          get_mark_tx_sdu_handler() override { return *this; }
  mark_delivery_status_handler& get_mark_delivery_status_handler() override { return *this; }

  void add_drb(drb_id_t drb_id, uint8_t pdcp_sn_size) override;
  void remove_drb(drb_id_t drb_id) override;
  void add_mapping(qos_flow_id_t qfi, drb_id_t drb_id) override;
  void remove_mapping(drb_id_t drb_id) override;

  // mark_tx_sdu_handler (DL: GTP-U -> MARK -> SDAP)
  void handle_sdu(byte_buffer sdu, qos_flow_id_t qos_flow_id) override;

  // mark_rx_pdu_handler (UL: SDAP -> MARK -> GTP-U)
  void handle_pdu(byte_buffer pdu, qos_flow_id_t qfi) override;

  // mark_delivery_status_handler (Feedback from DU)
  void handle_delivery_status(const nru_dl_data_delivery_status& status, drb_id_t drb_id) override;

  // Testing helpers
  void                    set_prng_seed(uint32_t seed);
  void                    set_forced_l4s_prob(std::optional<double> p) { forced_p_l4s = p; }
  void                    set_forced_classic_prob(std::optional<double> p) { forced_p_classic = p; }
  const mark_flow_table&  get_flow_table() const { return flow_table; }
  const mark_queue_model* get_queue_model(drb_id_t drb_id) const;

private:
  mark_session_logger          logger;
  mark_session_trx_logger      logger_rx;
  uint32_t                     ue_index;
  pdu_session_id_t             psi;
  mark_rx_sdu_notifier&        rx_sdu_notifier;
  mark_tx_pdu_notifier&        tx_pdu_notifier;
  const mark_config            cfg;
  const std::atomic<uint32_t>& nof_ues;

  std::unordered_map<qos_flow_id_t, drb_id_t>    qfi_to_drb;
  std::unordered_map<drb_id_t, mark_queue_model> drb_queues;

  mark_flow_table flow_table;

  std::mt19937                           prng{12345};
  std::uniform_real_distribution<double> dist{0.0, 1.0};

  std::optional<double> forced_p_l4s;
  std::optional<double> forced_p_classic;

  std::chrono::microseconds last_eviction_time{};
};

} // namespace srs_cu_up

} // namespace srsran
