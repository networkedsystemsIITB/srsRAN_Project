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

#include "srsran/mark/mark_factory.h"
#include "mark_entity_impl.h"

namespace srsran {

namespace srs_cu_up {

std::unique_ptr<mark_entity> create_mark(mark_entity_creation_message& msg)
{
  srsran_assert(msg.rx_sdu_notifier != nullptr, "rx_sdu_notifier must not be nullptr");
  srsran_assert(msg.tx_pdu_notifier != nullptr, "tx_pdu_notifier must not be nullptr");
  return std::make_unique<mark_entity_impl>(
      msg.ue_index, msg.pdu_session_id, *msg.rx_sdu_notifier, *msg.tx_pdu_notifier, msg.cfg, msg.nof_ues);
}

} // namespace srs_cu_up

} // namespace srsran
