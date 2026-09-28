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
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <functional>

namespace srsran {

namespace srs_cu_up {

namespace ip {

static constexpr uint32_t DIVOPT = 16777216; // 2^24

enum ecn_codepoint : uint8_t {
  not_ect = 0,
  ect_1   = 1,
  ect_0   = 2,
  ce      = 3,
};

static constexpr uint8_t INET_ECN_MASK = 0x03;

static constexpr uint8_t IP_PROTO_TCP = 6;
static constexpr uint8_t IP_PROTO_UDP = 17;

static constexpr uint8_t TCP_OPT_EOL     = 0;
static constexpr uint8_t TCP_OPT_NOP     = 1;
static constexpr uint8_t TCP_OPT_ACCECN0 = 172;
static constexpr uint8_t TCP_OPT_ACCECN1 = 174;

struct five_tuple {
  uint32_t src_addr = 0;
  uint32_t dst_addr = 0;
  uint16_t src_port = 0;
  uint16_t dst_port = 0;
  uint8_t  protocol = 0;

  bool operator==(const five_tuple& other) const
  {
    return src_addr == other.src_addr && dst_addr == other.dst_addr && src_port == other.src_port &&
           dst_port == other.dst_port && protocol == other.protocol;
  }

  bool operator!=(const five_tuple& other) const { return !(*this == other); }
};

inline five_tuple reverse_five_tuple(const five_tuple& t)
{
  return {t.dst_addr, t.src_addr, t.dst_port, t.src_port, t.protocol};
}

struct parsed_packet {
  bool          is_valid       = false;
  bool          is_ipv4        = false;
  bool          is_fragment    = false;
  uint8_t       ihl_bytes      = 0;
  uint8_t       protocol       = 0;
  ecn_codepoint ecn            = not_ect;
  uint16_t      total_len      = 0;
  uint16_t      ip_id          = 0;
  uint16_t      ip_check       = 0;
  five_tuple    tuple          = {};
  bool          is_tcp         = false;
  bool          is_udp         = false;
  uint32_t      seq            = 0;
  uint32_t      ack_seq        = 0;
  uint8_t       tcp_doff_bytes = 0;
  bool          tcp_syn        = false;
  bool          tcp_ack        = false;
  uint16_t      tcp_check      = 0;
  uint16_t      udp_len        = 0;
  uint16_t      udp_check      = 0;
  size_t        l4_payload_len = 0;
};

/// RFC 1624 incremental checksum update for a 16-bit word change.
inline uint16_t update_checksum_16(uint16_t old_csum, uint16_t old_val, uint16_t new_val)
{
  uint32_t sum = (~old_csum & 0xffff) + (~old_val & 0xffff) + (new_val & 0xffff);
  while (sum >> 16) {
    sum = (sum >> 16) + (sum & 0xffff);
  }
  uint16_t res = ~sum & 0xffff;
  return (res == 0) ? 0xffff : res;
}

/// Computes the full 16-bit one's complement Internet checksum over a buffer range.
inline uint16_t compute_checksum(const uint8_t* data, size_t len)
{
  uint32_t sum = 0;
  while (len > 1) {
    sum += ((static_cast<uint32_t>(data[0]) << 8) | data[1]);
    data += 2;
    len -= 2;
  }
  if (len == 1) {
    sum += (static_cast<uint32_t>(data[0]) << 8);
  }
  while (sum >> 16) {
    sum = (sum >> 16) + (sum & 0xffff);
  }
  uint16_t res = ~sum & 0xffff;
  return (res == 0) ? 0xffff : res;
}

/// Helper to read contiguous bytes from byte_buffer starting at offset into dst.
inline size_t read_bytes(const byte_buffer& buf, size_t offset, uint8_t* dst, size_t len)
{
  if (offset >= buf.length()) {
    return 0;
  }
  size_t to_read = std::min(len, buf.length() - offset);
  for (size_t i = 0; i < to_read; ++i) {
    dst[i] = buf[offset + i];
  }
  return to_read;
}

/// Helper to write contiguous bytes into byte_buffer starting at offset from src.
inline size_t write_bytes(byte_buffer& buf, size_t offset, const uint8_t* src, size_t len)
{
  if (offset >= buf.length()) {
    return 0;
  }
  size_t to_write = std::min(len, buf.length() - offset);
  for (size_t i = 0; i < to_write; ++i) {
    buf[offset + i] = src[i];
  }
  return to_write;
}

/// Full IPv4 header checksum computation directly from byte_buffer.
inline uint16_t compute_ip_checksum(const byte_buffer& buf, size_t ip_offset, size_t ihl_bytes)
{
  std::array<uint8_t, 60> hdr;
  if (ihl_bytes > sizeof(hdr) || ip_offset + ihl_bytes > buf.length()) {
    return 0;
  }
  read_bytes(buf, ip_offset, hdr.data(), ihl_bytes);
  hdr[10] = 0;
  hdr[11] = 0;
  return compute_checksum(hdr.data(), ihl_bytes);
}

/// Full TCP checksum computation from byte_buffer including pseudo-header.
inline uint16_t compute_tcp_checksum(const byte_buffer& buf, size_t ip_offset, size_t ihl_bytes, size_t tcp_len)
{
  if (ip_offset + ihl_bytes + tcp_len > buf.length()) {
    return 0;
  }
  std::array<uint8_t, 20> ip_hdr;
  read_bytes(buf, ip_offset, ip_hdr.data(), sizeof(ip_hdr));

  uint32_t sum = 0;
  // Pseudo-header: source IP (bytes 12..15)
  sum += (static_cast<uint32_t>(ip_hdr[12]) << 8) | ip_hdr[13];
  sum += (static_cast<uint32_t>(ip_hdr[14]) << 8) | ip_hdr[15];
  // Pseudo-header: destination IP (bytes 16..19)
  sum += (static_cast<uint32_t>(ip_hdr[16]) << 8) | ip_hdr[17];
  sum += (static_cast<uint32_t>(ip_hdr[18]) << 8) | ip_hdr[19];
  // Pseudo-header: zero + protocol (6)
  sum += IP_PROTO_TCP;
  // Pseudo-header: TCP length
  sum += static_cast<uint32_t>(tcp_len);

  size_t tcp_offset = ip_offset + ihl_bytes;
  size_t rem        = tcp_len;
  size_t idx        = 0;
  while (rem > 1) {
    if (idx == 16) {
      // Skip original checksum field
      idx += 2;
      rem -= 2;
      continue;
    }
    sum += (static_cast<uint32_t>(buf[tcp_offset + idx]) << 8) | buf[tcp_offset + idx + 1];
    idx += 2;
    rem -= 2;
  }
  if (rem == 1) {
    sum += static_cast<uint32_t>(buf[tcp_offset + idx]) << 8;
  }

  while (sum >> 16) {
    sum = (sum >> 16) + (sum & 0xffff);
  }
  uint16_t res = ~sum & 0xffff;
  return (res == 0) ? 0xffff : res;
}

/// Parses an IPv4 packet (and its TCP/UDP header if present) from a byte_buffer.
inline parsed_packet parse_packet(const byte_buffer& buf)
{
  parsed_packet pkt;
  if (buf.length() < 20) {
    return pkt;
  }

  uint8_t ver_ihl = buf[0];
  uint8_t version = ver_ihl >> 4;
  if (version != 4) {
    return pkt;
  }
  pkt.is_ipv4 = true;

  uint8_t ihl   = ver_ihl & 0x0f;
  pkt.ihl_bytes = ihl * 4;
  if (pkt.ihl_bytes < 20 || buf.length() < pkt.ihl_bytes) {
    return pkt;
  }

  pkt.total_len = (static_cast<uint16_t>(buf[2]) << 8) | buf[3];
  if (pkt.total_len < pkt.ihl_bytes || buf.length() < pkt.total_len) {
    return pkt;
  }

  uint16_t frag_off = (static_cast<uint16_t>(buf[6]) << 8) | buf[7];
  if ((frag_off & 0x3fff) != 0) {
    pkt.is_fragment = true;
    pkt.is_valid    = true;
    return pkt;
  }

  pkt.ecn      = static_cast<ecn_codepoint>(buf[1] & INET_ECN_MASK);
  pkt.ip_id    = (static_cast<uint16_t>(buf[4]) << 8) | buf[5];
  pkt.protocol = buf[9];
  pkt.ip_check = (static_cast<uint16_t>(buf[10]) << 8) | buf[11];

  pkt.tuple.src_addr = (static_cast<uint32_t>(buf[12]) << 24) | (static_cast<uint32_t>(buf[13]) << 16) |
                       (static_cast<uint32_t>(buf[14]) << 8) | buf[15];
  pkt.tuple.dst_addr = (static_cast<uint32_t>(buf[16]) << 24) | (static_cast<uint32_t>(buf[17]) << 16) |
                       (static_cast<uint32_t>(buf[18]) << 8) | buf[19];
  pkt.tuple.protocol = pkt.protocol;

  size_t l4_offset = pkt.ihl_bytes;
  if (pkt.protocol == IP_PROTO_TCP) {
    if (pkt.total_len < l4_offset + 20) {
      return pkt;
    }
    pkt.is_tcp         = true;
    pkt.tuple.src_port = (static_cast<uint16_t>(buf[l4_offset]) << 8) | buf[l4_offset + 1];
    pkt.tuple.dst_port = (static_cast<uint16_t>(buf[l4_offset + 2]) << 8) | buf[l4_offset + 3];
    pkt.seq = (static_cast<uint32_t>(buf[l4_offset + 4]) << 24) | (static_cast<uint32_t>(buf[l4_offset + 5]) << 16) |
              (static_cast<uint32_t>(buf[l4_offset + 6]) << 8) | buf[l4_offset + 7];
    pkt.ack_seq = (static_cast<uint32_t>(buf[l4_offset + 8]) << 24) |
                  (static_cast<uint32_t>(buf[l4_offset + 9]) << 16) |
                  (static_cast<uint32_t>(buf[l4_offset + 10]) << 8) | buf[l4_offset + 11];

    uint8_t tcp_doff   = (buf[l4_offset + 12] >> 4) & 0x0f;
    pkt.tcp_doff_bytes = tcp_doff * 4;
    if (pkt.tcp_doff_bytes < 20 || pkt.total_len < l4_offset + pkt.tcp_doff_bytes) {
      return pkt;
    }

    uint8_t flags      = buf[l4_offset + 13];
    pkt.tcp_syn        = (flags & 0x02) != 0;
    pkt.tcp_ack        = (flags & 0x10) != 0;
    pkt.tcp_check      = (static_cast<uint16_t>(buf[l4_offset + 16]) << 8) | buf[l4_offset + 17];
    pkt.l4_payload_len = pkt.total_len - pkt.ihl_bytes - pkt.tcp_doff_bytes;
    pkt.is_valid       = true;
  } else if (pkt.protocol == IP_PROTO_UDP) {
    if (pkt.total_len < l4_offset + 8) {
      return pkt;
    }
    pkt.is_udp         = true;
    pkt.tuple.src_port = (static_cast<uint16_t>(buf[l4_offset]) << 8) | buf[l4_offset + 1];
    pkt.tuple.dst_port = (static_cast<uint16_t>(buf[l4_offset + 2]) << 8) | buf[l4_offset + 3];
    pkt.udp_len        = (static_cast<uint16_t>(buf[l4_offset + 4]) << 8) | buf[l4_offset + 5];
    pkt.udp_check      = (static_cast<uint16_t>(buf[l4_offset + 6]) << 8) | buf[l4_offset + 7];
    pkt.l4_payload_len = pkt.total_len - pkt.ihl_bytes - 8;
    pkt.is_valid       = true;
  } else {
    // Non-TCP/UDP IPv4 packet
    pkt.is_valid = true;
  }

  return pkt;
}

/// Sets the ECN field in an IPv4 packet and updates its header checksum incrementally (RFC 1624).
inline bool set_ip_ecn(byte_buffer& buf, size_t ip_offset, ecn_codepoint new_ecn)
{
  if (buf.length() < ip_offset + 20) {
    return false;
  }
  uint8_t  old_tos  = buf[ip_offset + 1];
  uint8_t  new_tos  = (old_tos & ~INET_ECN_MASK) | (static_cast<uint8_t>(new_ecn) & INET_ECN_MASK);
  uint16_t old_word = (static_cast<uint16_t>(buf[ip_offset]) << 8) | old_tos;
  uint16_t new_word = (static_cast<uint16_t>(buf[ip_offset]) << 8) | new_tos;
  if (old_word == new_word) {
    return true;
  }

  uint16_t old_csum = (static_cast<uint16_t>(buf[ip_offset + 10]) << 8) | buf[ip_offset + 11];
  uint16_t new_csum = update_checksum_16(old_csum, old_word, new_word);

  buf[ip_offset + 1]  = new_tos;
  buf[ip_offset + 10] = static_cast<uint8_t>(new_csum >> 8);
  buf[ip_offset + 11] = static_cast<uint8_t>(new_csum & 0xff);
  return true;
}

/// Parameters for AccECN ACK rewrite.
struct accecn_counters {
  size_t ce_pkt     = 0;
  size_t ecn0_bytes = 0;
  size_t ecn1_bytes = 0;
  size_t ce_bytes   = 0;
};

/// Rewrites AccECN ACE flags and option counters in a TCP packet, updating TCP checksum incrementally (RFC 1624).
inline bool rewrite_accecn_feedback(byte_buffer& buf, size_t ip_offset, size_t ihl_bytes, const accecn_counters& cnt)
{
  size_t tcp_offset = ip_offset + ihl_bytes;
  if (buf.length() < tcp_offset + 20) {
    return false;
  }

  uint8_t tcp_doff_bytes = ((buf[tcp_offset + 12] >> 4) & 0x0f) * 4;
  if (tcp_doff_bytes < 20 || buf.length() < tcp_offset + tcp_doff_bytes) {
    return false;
  }

  uint16_t tcp_csum = (static_cast<uint16_t>(buf[tcp_offset + 16]) << 8) | buf[tcp_offset + 17];

  // 1. Rewrite ACE bits in TCP flags:
  // Byte 12 is [data offset:4][reserved:3][AE:1] and byte 13 is [CWR ECE URG ACK PSH RST SYN FIN].
  // bit 2 -> AE (bit 0 of byte 12)
  // bit 1 -> CWR (bit 7 of byte 13)
  // bit 0 -> ECE (bit 6 of byte 13)
  uint16_t old_flags_word = (static_cast<uint16_t>(buf[tcp_offset + 12]) << 8) | buf[tcp_offset + 13];

  uint8_t b12 = buf[tcp_offset + 12];
  uint8_t b13 = buf[tcp_offset + 13];

  uint8_t ae_bit  = (cnt.ce_pkt & 0x04) ? 1 : 0;
  uint8_t cwr_bit = (cnt.ce_pkt & 0x02) ? 1 : 0;
  uint8_t ece_bit = (cnt.ce_pkt & 0x01) ? 1 : 0;

  // Set bit 0 of byte 12 for AE
  b12 = (b12 & ~0x01) | ae_bit;
  // Set bit 7 of byte 13 for CWR, bit 6 for ECE
  b13 = (b13 & ~0xc0) | (cwr_bit << 7) | (ece_bit << 6);

  uint16_t new_flags_word = (static_cast<uint16_t>(b12) << 8) | b13;
  if (old_flags_word != new_flags_word) {
    tcp_csum             = update_checksum_16(tcp_csum, old_flags_word, new_flags_word);
    buf[tcp_offset + 12] = b12;
    buf[tcp_offset + 13] = b13;
  }

  // 2. Search for AccECN options (kind 172 or 174) in the option area
  size_t opt_offset = 20;
  while (opt_offset < tcp_doff_bytes) {
    uint8_t opt_kind = buf[tcp_offset + opt_offset];
    if (opt_kind == TCP_OPT_EOL) {
      break;
    }
    if (opt_kind == TCP_OPT_NOP) {
      opt_offset += 1;
      continue;
    }

    if (opt_offset + 1 >= tcp_doff_bytes) {
      break;
    }
    uint8_t opt_len = buf[tcp_offset + opt_offset + 1];
    if (opt_len < 2 || opt_offset + opt_len > tcp_doff_bytes) {
      break;
    }

    if (opt_kind == TCP_OPT_ACCECN0 || opt_kind == TCP_OPT_ACCECN1) {
      // Form counter bytes to write based on option kind
      // Kind 172 (AccECN0): e0b (3 bytes), ceb (3 bytes), e1b (3 bytes)
      // Kind 174 (AccECN1): e1b (3 bytes), ceb (3 bytes), e0b (3 bytes)
      std::array<uint8_t, 9> raw_counters{};
      uint32_t               c0 = (opt_kind == TCP_OPT_ACCECN0) ? cnt.ecn0_bytes : cnt.ecn1_bytes;
      uint32_t               c1 = cnt.ce_bytes;
      uint32_t               c2 = (opt_kind == TCP_OPT_ACCECN0) ? cnt.ecn1_bytes : cnt.ecn0_bytes;

      raw_counters[0] = static_cast<uint8_t>((c0 >> 16) & 0xff);
      raw_counters[1] = static_cast<uint8_t>((c0 >> 8) & 0xff);
      raw_counters[2] = static_cast<uint8_t>(c0 & 0xff);

      raw_counters[3] = static_cast<uint8_t>((c1 >> 16) & 0xff);
      raw_counters[4] = static_cast<uint8_t>((c1 >> 8) & 0xff);
      raw_counters[5] = static_cast<uint8_t>(c1 & 0xff);

      raw_counters[6] = static_cast<uint8_t>((c2 >> 16) & 0xff);
      raw_counters[7] = static_cast<uint8_t>((c2 >> 8) & 0xff);
      raw_counters[8] = static_cast<uint8_t>(c2 & 0xff);

      // Only write fields that fit in opt_len:
      // opt_len 2: 0 bytes
      // opt_len 5: 3 bytes
      // opt_len 8: 6 bytes
      // opt_len 11: 9 bytes
      size_t bytes_to_write = 0;
      if (opt_len >= 11) {
        bytes_to_write = 9;
      } else if (opt_len >= 8) {
        bytes_to_write = 6;
      } else if (opt_len >= 5) {
        bytes_to_write = 3;
      }

      if (bytes_to_write > 0) {
        size_t write_start = tcp_offset + opt_offset + 2;
        size_t write_end   = write_start + bytes_to_write;

        // Align to 16-bit boundaries relative to tcp_offset
        size_t align_start = tcp_offset + ((write_start - tcp_offset) & ~1ULL);
        size_t align_end   = tcp_offset + (((write_end - tcp_offset) + 1) & ~1ULL);

        for (size_t pos = align_start; pos < align_end; pos += 2) {
          uint16_t old_w = (static_cast<uint16_t>(buf[pos]) << 8) | buf[pos + 1];

          // Modify bytes within [write_start, write_end)
          if (pos >= write_start && pos < write_end) {
            buf[pos] = raw_counters[pos - write_start];
          }
          if (pos + 1 >= write_start && pos + 1 < write_end) {
            buf[pos + 1] = raw_counters[pos + 1 - write_start];
          }

          uint16_t new_w = (static_cast<uint16_t>(buf[pos]) << 8) | buf[pos + 1];
          if (old_w != new_w) {
            tcp_csum = update_checksum_16(tcp_csum, old_w, new_w);
          }
        }
      }
      break;
    }

    opt_offset += opt_len;
  }

  buf[tcp_offset + 16] = static_cast<uint8_t>(tcp_csum >> 8);
  buf[tcp_offset + 17] = static_cast<uint8_t>(tcp_csum & 0xff);
  return true;
}

} // namespace ip

} // namespace srs_cu_up

} // namespace srsran

namespace std {

template <>
struct hash<srsran::srs_cu_up::ip::five_tuple> {
  std::size_t operator()(const srsran::srs_cu_up::ip::five_tuple& k) const
  {
    return ((((((hash<uint32_t>()(k.src_addr) ^ (hash<uint32_t>()(k.dst_addr) << 1)) >> 1) ^
               (hash<uint16_t>()(k.src_port) << 1)) >>
              1) ^
             (hash<uint16_t>()(k.dst_port) << 1)) >>
            1) ^
           hash<uint8_t>()(k.protocol);
  }
};

} // namespace std
