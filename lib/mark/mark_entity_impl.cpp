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

#include "mark_entity_impl.h"
#include <chrono>

namespace srsran {

namespace srs_cu_up {

mark_entity_impl::mark_entity_impl(uint32_t                     ue_index_,
                                   pdu_session_id_t             psi_,
                                   mark_rx_sdu_notifier&        rx_sdu_notifier_,
                                   mark_tx_pdu_notifier&        tx_pdu_notifier_,
                                   const mark_config&           cfg_,
                                   const std::atomic<uint32_t>& nof_ues_) :
  logger("MARK", {ue_index_, psi_}),
  logger_rx("MARK", {ue_index_, psi_, "UL"}),
  ue_index(ue_index_),
  psi(psi_),
  rx_sdu_notifier(rx_sdu_notifier_),
  tx_pdu_notifier(tx_pdu_notifier_),
  cfg(cfg_),
  nof_ues(nof_ues_)
{
}

void mark_entity_impl::set_prng_seed(uint32_t seed)
{
  prng.seed(seed);
}

const mark_queue_model* mark_entity_impl::get_queue_model(drb_id_t drb_id) const
{
  auto it = drb_queues.find(drb_id);
  if (it != drb_queues.end()) {
    return &it->second;
  }
  return nullptr;
}

void mark_entity_impl::add_drb(drb_id_t drb_id, uint8_t pdcp_sn_size)
{
  drb_queues.emplace(drb_id, mark_queue_model(pdcp_sn_size, cfg));
  logger.log_debug("Added {} pdcp_sn_size={}", drb_id, pdcp_sn_size);
}

void mark_entity_impl::remove_drb(drb_id_t drb_id)
{
  drb_queues.erase(drb_id);
  remove_mapping(drb_id);
  logger.log_debug("Removed {}", drb_id);
}

void mark_entity_impl::add_mapping(qos_flow_id_t qfi, drb_id_t drb_id)
{
  qfi_to_drb[qfi] = drb_id;
}

void mark_entity_impl::remove_mapping(drb_id_t drb_id)
{
  for (auto it = qfi_to_drb.begin(); it != qfi_to_drb.end();) {
    if (it->second == drb_id) {
      it = qfi_to_drb.erase(it);
    } else {
      ++it;
    }
  }
}

void mark_entity_impl::handle_sdu(byte_buffer sdu, qos_flow_id_t qos_flow_id)
{
  auto now = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::system_clock::now().time_since_epoch());

  // Periodically evict idle flows (O(1) check)
  if (last_eviction_time.count() == 0 ||
      (now - last_eviction_time) >= std::chrono::milliseconds(cfg.flow_idle_timeout_ms)) {
    flow_table.evict_idle_flows(now, cfg.flow_idle_timeout_ms);
    last_eviction_time = now;
  }

  // SDUs of unmapped QoS flows are dropped by SDAP, so they must not be accounted in any DRB queue model.
  auto qfi_it = qfi_to_drb.find(qos_flow_id);
  if (qfi_it == qfi_to_drb.end()) {
    tx_pdu_notifier.on_new_pdu(std::move(sdu), qos_flow_id);
    return;
  }
  drb_id_t drb_id   = qfi_it->second;
  auto     queue_it = drb_queues.find(drb_id);

  ip::parsed_packet pkt = ip::parse_packet(sdu);

  if (!pkt.is_valid || !pkt.is_ipv4 || pkt.is_fragment) {
    // Non-IPv4 or fragmented packet: push to shadow queue model (per §6.3), pass through untouched
    if (queue_it != drb_queues.end()) {
      queue_it->second.push_sdu(sdu.length(), now, ip::ecn_codepoint::not_ect, false);
    }
    tx_pdu_notifier.on_new_pdu(std::move(sdu), qos_flow_id);
    return;
  }

  // Record packet in the shadow queue model
  if (queue_it != drb_queues.end()) {
    queue_it->second.push_sdu(sdu.length(), now, pkt.ecn, pkt.is_tcp && pkt.tcp_syn);
  }

  // Determine marking probability
  double p = 0.0;
  if (pkt.ecn == ip::ecn_codepoint::ect_1) {
    if (forced_p_l4s.has_value()) {
      p = forced_p_l4s.value();
    } else if (queue_it != drb_queues.end()) {
      p = queue_it->second.get_p_l4s(now);
    }
  } else if (pkt.ecn == ip::ecn_codepoint::ect_0) {
    if (forced_p_classic.has_value()) {
      p = forced_p_classic.value();
    } else if (queue_it != drb_queues.end()) {
      p = queue_it->second.get_p_classic(now);
    }
  }

  bool do_mark = false;
  if (p >= 1.0) {
    do_mark = true;
  } else if (p > 0.0) {
    do_mark = (dist(prng) < p);
  }

  // Signalling configured for the packet's class and transport. CE and Not-ECT packets are never marked.
  mark_signal signal = mark_signal::none;
  if (pkt.ecn == ip::ecn_codepoint::ect_1) {
    signal = pkt.is_tcp ? cfg.l4s.tcp : cfg.l4s.udp;
  } else if (pkt.ecn == ip::ecn_codepoint::ect_0) {
    signal = pkt.is_tcp ? cfg.classic.tcp : cfg.classic.udp;
  }

  if (pkt.is_udp) {
    if (signal == mark_signal::dl_ce && do_mark) {
      ip::set_ip_ecn(sdu, 0, ip::ecn_codepoint::ce);
      logger.log_debug("CE-marked DL UDP packet. {} ecn={} p={:.3f}", drb_id, static_cast<unsigned>(pkt.ecn), p);
    }
  } else if (pkt.is_tcp) {
    if (pkt.tcp_syn) {
      flow_table.map_flow(pkt.tuple, drb_id, now, cfg.ack_rewrite.ce_pkt_offset);
    } else if (signal == mark_signal::dl_ce) {
      // CE-mark the DL packet itself, so that any ECN-capable receiver (RFC 3168 or AccECN) echoes it.
      if (do_mark) {
        ip::set_ip_ecn(sdu, 0, ip::ecn_codepoint::ce);
        logger.log_debug("CE-marked DL TCP packet. {} ecn={} p={:.3f}", drb_id, static_cast<unsigned>(pkt.ecn), p);
      }
    } else {
      // Leave the DL packet unmarked. With ack_rewrite, count a virtual CE that is reported through the UL AccECN
      // rewrite. CE marks from upstream hops are always counted.
      bool count_as_ce = (signal == mark_signal::ack_rewrite && do_mark) || pkt.ecn == ip::ecn_codepoint::ce;
      flow_table.update_dl_flow(
          pkt.tuple, drb_id, now, pkt.ecn, count_as_ce, pkt.l4_payload_len, cfg.ack_rewrite.ce_pkt_offset);
    }
  }

  tx_pdu_notifier.on_new_pdu(std::move(sdu), qos_flow_id);
}

void mark_entity_impl::handle_pdu(byte_buffer pdu, qos_flow_id_t qfi)
{
  auto now = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::system_clock::now().time_since_epoch());

  ip::parsed_packet pkt = ip::parse_packet(pdu);

  if (pkt.is_valid && pkt.is_ipv4 && !pkt.is_fragment && pkt.is_tcp && pkt.tcp_ack) {
    ip::five_tuple rev_tuple = ip::reverse_five_tuple(pkt.tuple);
    auto           entry     = flow_table.get_and_update_ack(rev_tuple, pkt.ack_seq, now);

    if (entry.has_value()) {
      const auto& f              = entry.value();
      size_t      pkt_size       = (cfg.ack_rewrite.mss_bytes > 0) ? cfg.ack_rewrite.mss_bytes : 1336;
      size_t      offset         = cfg.ack_rewrite.ce_pkt_offset;
      size_t      total_pkt      = 0;
      size_t      ce_pkt         = offset;
      size_t      ce_bytes       = 0;
      size_t      ecn0_bytes     = 1;
      size_t      ecn1_bytes     = 1;
      bool        should_rewrite = false;

      // Bytes acknowledged since the first ACK of the flow, modulo 2^32 (TCP sequence numbers wrap).
      uint32_t acked_bytes = pkt.ack_seq - f.ack_raw;
      if (acked_bytes > 1) {
        total_pkt = (acked_bytes - 1) / pkt_size;
      }

      // The class (L4S or classic) of the DL flow decides, not the ECN codepoint of the ACK, which is usually Not-ECT.
      bool l4s_rewrite     = f.ect == ip::ecn_codepoint::ect_1 && cfg.l4s.tcp == mark_signal::ack_rewrite;
      bool classic_rewrite = f.ect == ip::ecn_codepoint::ect_0 && cfg.classic.tcp == mark_signal::ack_rewrite;

      if (l4s_rewrite && f.pkts_with_ecn1 > 0 && f.pkts_with_ce > offset) {
        double portion =
            static_cast<double>(f.bytes_with_ce) / static_cast<double>(f.bytes_with_ecn1 + f.bytes_with_ce);
        portion *= cfg.ack_rewrite.l4s_ce_scale; // Default / 10
        ce_pkt = static_cast<size_t>(total_pkt * portion) + offset;
        ce_bytes =
            (ce_pkt * pkt_size >= offset * pkt_size) ? ((ce_pkt * pkt_size - offset * pkt_size) % ip::DIVOPT) : 0;
        if (acked_bytes >= ce_bytes) {
          ecn1_bytes = (acked_bytes - ce_bytes) % ip::DIVOPT;
        }
        should_rewrite = true;
      } else if (classic_rewrite && f.pkts_with_ecn0 > 0 && f.pkts_with_ce > offset) {
        double portion =
            static_cast<double>(f.bytes_with_ce) / static_cast<double>(f.bytes_with_ecn0 + f.bytes_with_ce);
        ce_pkt = static_cast<size_t>(total_pkt * portion) + offset;
        ce_bytes =
            (ce_pkt * pkt_size >= offset * pkt_size) ? ((ce_pkt * pkt_size - offset * pkt_size) % ip::DIVOPT) : 0;
        if (acked_bytes >= ce_bytes) {
          ecn0_bytes = (acked_bytes - ce_bytes) % ip::DIVOPT;
        }
        ecn1_bytes     = 1;
        should_rewrite = true;
      }

      if (should_rewrite) {
        ip::accecn_counters cnt{};
        cnt.ce_pkt     = ce_pkt;
        cnt.ecn0_bytes = ecn0_bytes;
        cnt.ecn1_bytes = ecn1_bytes;
        cnt.ce_bytes   = ce_bytes;
        ip::rewrite_accecn_feedback(pdu, 0, pkt.ihl_bytes, cnt);
        logger_rx.log_debug("Rewrote AccECN feedback. {} ack={} ce_pkt={} ce_bytes={} ecn0_bytes={} ecn1_bytes={}",
                            f.drb_id,
                            pkt.ack_seq,
                            ce_pkt,
                            ce_bytes,
                            ecn0_bytes,
                            ecn1_bytes);
      }
    }
  }

  rx_sdu_notifier.on_new_sdu(std::move(pdu), qfi);
}

void mark_entity_impl::handle_delivery_status(const nru_dl_data_delivery_status& status, drb_id_t drb_id)
{
  auto now = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::system_clock::now().time_since_epoch());

  auto it = drb_queues.find(drb_id);
  if (it == drb_queues.end()) {
    return;
  }
  mark_queue_model& model = it->second;

  uint32_t nof_resyncs = model.get_nof_resyncs();
  if (!model.process_delivery_status(status, now, nof_ues.load(std::memory_order_relaxed))) {
    return;
  }
  if (model.get_nof_resyncs() != nof_resyncs) {
    logger.log_warning("Feedback ran ahead of the queue model, resynchronised head to tail. {} next_tx_id={}",
                       drb_id,
                       model.get_next_tx_id());
  }
  logger.log_debug("Marking decision. {} standing_q={:.0f}B pred_rate={:.3f}B/us pred_err={:.3f}B/us "
                   "est_qdelay={:.0f}us l4s={} classic={} p_l4s={:.3f} p_classic={:.3f}",
                   drb_id,
                   model.get_standing_queue_bytes(),
                   model.get_pred_rate(),
                   model.get_pred_error(),
                   model.get_est_qdelay_us(),
                   model.have_l4s(now),
                   model.have_classic(now),
                   model.get_raw_p_l4s(),
                   model.get_raw_p_classic());
}

} // namespace srs_cu_up

} // namespace srsran
