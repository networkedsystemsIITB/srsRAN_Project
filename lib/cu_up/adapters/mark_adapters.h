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

#include "srsran/f1u/cu_up/f1u_rx_delivery_status_observer.h"
#include "srsran/gtpu/gtpu_tunnel_ngu_rx.h"
#include "srsran/gtpu/gtpu_tunnel_ngu_tx.h"
#include "srsran/mark/mark.h"
#include "srsran/sdap/sdap.h"
#include "srsran/srslog/srslog.h"
#include "srsran/support/executors/task_executor.h"

namespace srsran {
namespace srs_cu_up {

/// Adapter between GTP-U Rx (DL) and MARK Tx
class gtpu_mark_adapter : public gtpu_tunnel_ngu_rx_lower_layer_notifier
{
public:
  gtpu_mark_adapter()           = default;
  ~gtpu_mark_adapter() override = default;

  void connect_mark(mark_tx_sdu_handler& mark_handler_) { mark_handler = &mark_handler_; }
  void disconnect() { mark_handler = nullptr; }

  void on_new_sdu(byte_buffer sdu, qos_flow_id_t qos_flow_id) override
  {
    srsran_assert(mark_handler != nullptr, "MARK handler must not be nullptr");
    mark_handler->handle_sdu(std::move(sdu), qos_flow_id);
  }

private:
  mark_tx_sdu_handler* mark_handler = nullptr;
};

/// Adapter between MARK Tx (DL) and SDAP Tx
class mark_sdap_adapter : public mark_tx_pdu_notifier
{
public:
  mark_sdap_adapter()           = default;
  ~mark_sdap_adapter() override = default;

  void connect_sdap(sdap_tx_sdu_handler& sdap_handler_) { sdap_handler = &sdap_handler_; }
  void disconnect() { sdap_handler = nullptr; }

  void on_new_pdu(byte_buffer pdu, qos_flow_id_t qfi) override
  {
    srsran_assert(sdap_handler != nullptr, "SDAP handler must not be nullptr");
    sdap_handler->handle_sdu(std::move(pdu), qfi);
  }

private:
  sdap_tx_sdu_handler* sdap_handler = nullptr;
};

/// Adapter between SDAP Rx (UL) and MARK Rx
class sdap_mark_adapter : public sdap_rx_sdu_notifier
{
public:
  sdap_mark_adapter()           = default;
  ~sdap_mark_adapter() override = default;

  void connect_mark(mark_rx_pdu_handler& mark_handler_) { mark_handler = &mark_handler_; }
  void disconnect() { mark_handler = nullptr; }

  void on_new_sdu(byte_buffer sdu, qos_flow_id_t qfi) override
  {
    srsran_assert(mark_handler != nullptr, "MARK handler must not be nullptr");
    mark_handler->handle_pdu(std::move(sdu), qfi);
  }

private:
  mark_rx_pdu_handler* mark_handler = nullptr;
};

/// Adapter between MARK Rx (UL) and GTP-U Tx
class mark_gtpu_adapter : public mark_rx_sdu_notifier
{
public:
  mark_gtpu_adapter()           = default;
  ~mark_gtpu_adapter() override = default;

  void connect_gtpu(gtpu_tunnel_ngu_tx_lower_layer_interface& gtpu_handler_) { gtpu_handler = &gtpu_handler_; }
  void disconnect() { gtpu_handler = nullptr; }

  void on_new_sdu(byte_buffer sdu, qos_flow_id_t qfi) override
  {
    srsran_assert(gtpu_handler != nullptr, "GTPU handler must not be nullptr");
    gtpu_handler->handle_sdu(std::move(sdu), qfi);
  }

private:
  gtpu_tunnel_ngu_tx_lower_layer_interface* gtpu_handler = nullptr;
};

/// Adapter between F1-U DDDS observer and MARK queue model, deferring to ue_dl_exec
class f1u_mark_adapter : public f1u_rx_delivery_status_observer
{
public:
  f1u_mark_adapter()           = default;
  ~f1u_mark_adapter() override = default;

  void connect_mark(mark_delivery_status_handler& handler, drb_id_t drb_id_, task_executor& dl_exec_)
  {
    mark_handler = &handler;
    drb_id       = drb_id_;
    dl_exec      = &dl_exec_;
  }

  void disconnect()
  {
    mark_handler = nullptr;
    dl_exec      = nullptr;
  }

  void on_delivery_status(const nru_dl_data_delivery_status& status) override
  {
    if (dl_exec == nullptr || mark_handler == nullptr) {
      return;
    }
    // Capture the handler and DRB ID by value rather than this adapter: the adapter belongs to the DRB context, which
    // can be destroyed by a higher-priority control task before this DL task runs. MARK ignores unknown DRBs.
    if (not dl_exec->defer(
            [handler = mark_handler, drb = drb_id, status]() { handler->handle_delivery_status(status, drb); })) {
      srslog::fetch_basic_logger("MARK").warning("Dropped F1-U delivery status for {}, task queue is full", drb_id);
    }
  }

private:
  mark_delivery_status_handler* mark_handler = nullptr;
  drb_id_t                      drb_id       = drb_id_t::drb1;
  task_executor*                dl_exec      = nullptr;
};

} // namespace srs_cu_up
} // namespace srsran
