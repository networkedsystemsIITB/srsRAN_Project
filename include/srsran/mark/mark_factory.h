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

#include "srsran/mark/mark.h"
#include "srsran/mark/mark_config.h"
#include "srsran/ran/cu_types.h"
#include <atomic>
#include <memory>

namespace srsran {

namespace srs_cu_up {

struct mark_entity_creation_message {
  uint32_t                     ue_index;
  pdu_session_id_t             pdu_session_id;
  mark_rx_sdu_notifier*        rx_sdu_notifier;
  mark_tx_pdu_notifier*        tx_pdu_notifier;
  const mark_config&           cfg;
  const std::atomic<uint32_t>& nof_ues;
};

/// Creates an instance of a MARK entity.
std::unique_ptr<mark_entity> create_mark(mark_entity_creation_message& msg);

} // namespace srs_cu_up

} // namespace srsran
