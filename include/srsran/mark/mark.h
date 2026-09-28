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

#include "srsran/adt/byte_buffer.h"
#include "srsran/nru/nru_message.h"
#include "srsran/ran/cu_types.h"
#include "srsran/ran/rb_id.h"

namespace srsran {

namespace srs_cu_up {

/// Entry point of the receiving side (UL: SDAP -> MARK -> GTP-U) of a MARK entity.
class mark_rx_pdu_handler
{
public:
  virtual ~mark_rx_pdu_handler() = default;

  /// Handle the incoming UL PDU.
  virtual void handle_pdu(byte_buffer pdu, qos_flow_id_t qfi) = 0;
};

/// Notifies upper layers (GTP-U) of new UL SDUs.
class mark_rx_sdu_notifier
{
public:
  virtual ~mark_rx_sdu_notifier() = default;

  /// Invoked on each generated UL SDU.
  virtual void on_new_sdu(byte_buffer sdu, qos_flow_id_t qfi) = 0;
};

/// Entry point of the transmitting side (DL: GTP-U -> MARK -> SDAP) of a MARK entity.
class mark_tx_sdu_handler
{
public:
  virtual ~mark_tx_sdu_handler() = default;

  /// Handle the incoming DL SDU.
  virtual void handle_sdu(byte_buffer sdu, qos_flow_id_t qos_flow_id) = 0;
};

/// Notifies lower layers (SDAP) of new DL PDUs.
class mark_tx_pdu_notifier
{
public:
  virtual ~mark_tx_pdu_notifier() = default;

  /// Invoked on each generated DL PDU.
  virtual void on_new_pdu(byte_buffer pdu, qos_flow_id_t qfi) = 0;
};

/// Handles DDDS delivery feedback from the DU.
class mark_delivery_status_handler
{
public:
  virtual ~mark_delivery_status_handler() = default;

  /// Invoked when a new DDDS status arrives for a DRB.
  virtual void handle_delivery_status(const nru_dl_data_delivery_status& status, drb_id_t drb_id) = 0;
};

/// Interface for the MARK entity.
class mark_entity
{
public:
  virtual ~mark_entity() = default;

  virtual mark_rx_pdu_handler&          get_mark_rx_pdu_handler()          = 0;
  virtual mark_tx_sdu_handler&          get_mark_tx_sdu_handler()          = 0;
  virtual mark_delivery_status_handler& get_mark_delivery_status_handler() = 0;

  virtual void add_drb(drb_id_t drb_id, uint8_t pdcp_sn_size)  = 0;
  virtual void remove_drb(drb_id_t drb_id)                     = 0;
  virtual void add_mapping(qos_flow_id_t qfi, drb_id_t drb_id) = 0;
  virtual void remove_mapping(drb_id_t drb_id)                 = 0;
};

} // namespace srs_cu_up

} // namespace srsran
