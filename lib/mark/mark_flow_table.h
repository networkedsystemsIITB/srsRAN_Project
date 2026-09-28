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
#include "srsran/ran/rb_id.h"
#include <chrono>
#include <mutex>
#include <optional>
#include <unordered_map>

namespace srsran {

namespace srs_cu_up {

struct flow_entry {
  drb_id_t                  drb_id          = drb_id_t::drb1;
  std::chrono::microseconds last_seen       = {};
  size_t                    bytes_with_ecn1 = 1;
  size_t                    bytes_with_ecn0 = 1;
  size_t                    bytes_with_ce   = 0;
  size_t                    pkts_with_ecn1  = 0;
  size_t                    pkts_with_ecn0  = 0;
  size_t                    pkts_with_ce    = 0;
  uint32_t                  ack_raw         = 0;
  bool                      ack_raw_init    = false;
  bool                      initialized     = false;
  /// ECT codepoint of the flow's DL data packets, which decides its class (L4S or classic) for the UL ACK rewrite.
  ip::ecn_codepoint ect = ip::ecn_codepoint::not_ect;
};

class mark_flow_table
{
public:
  mark_flow_table()  = default;
  ~mark_flow_table() = default;

  /// Updates flow counters on the DL path.
  void update_dl_flow(const ip::five_tuple&     tuple,
                      drb_id_t                  drb_id,
                      std::chrono::microseconds now,
                      ip::ecn_codepoint         ecn,
                      bool                      marked,
                      size_t                    payload_len,
                      uint32_t                  initial_ce_offset)
  {
    std::lock_guard<std::mutex> lock(mutex);
    auto&                       entry = table[tuple];
    entry.drb_id                      = drb_id;
    entry.last_seen                   = now;

    if (!entry.initialized) {
      entry.pkts_with_ce = initial_ce_offset;
      entry.initialized  = true;
    }
    if (ecn == ip::ecn_codepoint::ect_0 || ecn == ip::ecn_codepoint::ect_1) {
      entry.ect = ecn;
    }

    if (ecn == ip::ecn_codepoint::ect_1) {
      if (marked) {
        entry.pkts_with_ce += 1;
        entry.bytes_with_ce += payload_len;
      } else {
        entry.pkts_with_ecn1 += 1;
        entry.bytes_with_ecn1 += payload_len;
      }
    } else if (ecn == ip::ecn_codepoint::ect_0) {
      if (marked) {
        entry.pkts_with_ce += 1;
        entry.bytes_with_ce += payload_len;
      } else {
        entry.pkts_with_ecn0 += 1;
        entry.bytes_with_ecn0 += payload_len;
      }
    } else if (ecn == ip::ecn_codepoint::ce) {
      entry.pkts_with_ce += 1;
      entry.bytes_with_ce += payload_len;
    }
  }

  /// Sets / maps the flow to a DRB without incrementing data packet counters (e.g. for SYN).
  void map_flow(const ip::five_tuple& tuple, drb_id_t drb_id, std::chrono::microseconds now, uint32_t initial_ce_offset)
  {
    std::lock_guard<std::mutex> lock(mutex);
    auto&                       entry = table[tuple];
    entry.drb_id                      = drb_id;
    entry.last_seen                   = now;
    if (!entry.initialized) {
      entry.pkts_with_ce = initial_ce_offset;
      entry.initialized  = true;
    }
  }

  /// Looks up and updates ACK raw for an incoming UL TCP ACK.
  /// Returns a snapshot of the flow entry if found.
  std::optional<flow_entry>
  get_and_update_ack(const ip::five_tuple& reverse_tuple, uint32_t ack_seq, std::chrono::microseconds now)
  {
    std::lock_guard<std::mutex> lock(mutex);
    auto                        it = table.find(reverse_tuple);
    if (it == table.end()) {
      return std::nullopt;
    }

    if (ack_seq > 0) {
      // Track the lowest ACK number seen, using serial number arithmetic so that 32-bit sequence wrap-around is not
      // mistaken for an older ACK.
      if (!it->second.ack_raw_init || static_cast<int32_t>(ack_seq - (it->second.ack_raw + 1)) < 0) {
        it->second.ack_raw      = ack_seq - 1;
        it->second.ack_raw_init = true;
      }
    }
    it->second.last_seen = now;
    return it->second;
  }

  /// Evicts flows that have been idle longer than timeout_ms.
  void evict_idle_flows(std::chrono::microseconds now, uint32_t timeout_ms)
  {
    std::lock_guard<std::mutex> lock(mutex);
    auto                        timeout = std::chrono::milliseconds(timeout_ms);
    for (auto it = table.begin(); it != table.end();) {
      if (now - it->second.last_seen > timeout) {
        it = table.erase(it);
      } else {
        ++it;
      }
    }
  }

  /// Returns a snapshot of the flow entry if found (read-only).
  std::optional<flow_entry> get_flow(const ip::five_tuple& tuple) const
  {
    std::lock_guard<std::mutex> lock(mutex);
    auto                        it = table.find(tuple);
    if (it != table.end()) {
      return it->second;
    }
    return std::nullopt;
  }

  size_t size() const
  {
    std::lock_guard<std::mutex> lock(mutex);
    return table.size();
  }

  void clear()
  {
    std::lock_guard<std::mutex> lock(mutex);
    table.clear();
  }

private:
  mutable std::mutex                             mutex;
  std::unordered_map<ip::five_tuple, flow_entry> table;
};

} // namespace srs_cu_up

} // namespace srsran
