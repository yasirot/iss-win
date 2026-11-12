#include "proto/rtcp.h"

#include <algorithm>
#include <cmath>

namespace iss::proto::rtcp {
namespace {

constexpr uint64_t kNtpEpochDelta = 2208988800ull;  // 1900-01-01 → 1970-01-01

}  // namespace

Bytes build_fir(uint32_t sender_ssrc, uint32_t target_ssrc, uint8_t seq_nr) {
  return ByteWriter().u8(0x80 | 4).u8(206).be16(4).be32(sender_ssrc).be32(0).be32(target_ssrc).u8(seq_nr).zeros(3).take();
}

Bytes build_fir_legacy(uint32_t target_ssrc) { return ByteWriter().u8(0x80).u8(192).be16(1).be32(target_ssrc).take(); }

Bytes build_pli(uint32_t sender_ssrc, uint32_t media_ssrc) {
  return ByteWriter().u8(0x80 | 1).u8(206).be16(2).be32(sender_ssrc).be32(media_ssrc).take();
}

Bytes build_nack(uint32_t sender_ssrc, uint32_t media_ssrc, std::vector<uint16_t> lost) {
  std::sort(lost.begin(), lost.end());
  lost.erase(std::unique(lost.begin(), lost.end()), lost.end());
  if (lost.empty()) return {};
  ByteWriter fci;
  size_t n_fci = 0;
  for (size_t i = 0; i < lost.size();) {
    const uint16_t pid = lost[i];
    uint16_t blp = 0;
    size_t j = i + 1;
    for (; j < lost.size(); ++j) {
      const uint16_t diff = static_cast<uint16_t>(lost[j] - pid);
      if (diff < 1 || diff > 16) break;
      blp |= static_cast<uint16_t>(1u << (diff - 1));
    }
    fci.be16(pid).be16(blp);
    ++n_fci;
    i = j;
  }
  return ByteWriter()
      .u8(0x80 | 1)
      .u8(205)
      .be16(static_cast<uint16_t>(2 + n_fci))
      .be32(sender_ssrc)
      .be32(media_ssrc)
      .bytes(fci.take())
      .take();
}

Bytes build_app_ltrp(uint32_t sender_ssrc, uint32_t ltr_id) {
  return ByteWriter().u8(0x80).u8(204).be16(3).be32(sender_ssrc).be32(5).be32(ltr_id).take();
}

Bytes build_empty_sr(uint32_t sender_ssrc, double unix_time) {
  const double whole = std::floor(unix_time);
  const auto ntp_sec = static_cast<uint32_t>(static_cast<uint64_t>(whole) + kNtpEpochDelta);
  const auto ntp_frac = static_cast<uint32_t>((unix_time - whole) * 4294967296.0);
  const auto rtp_ts = static_cast<uint32_t>(static_cast<uint64_t>(unix_time * 90000.0));
  return ByteWriter()
      .u8(0x80)
      .u8(200)
      .be16(6)
      .be32(sender_ssrc)
      .be32(ntp_sec)
      .be32(ntp_frac)
      .be32(rtp_ts)
      .be32(0)
      .be32(0)
      .take();
}

Bytes build_rr(uint32_t sender_ssrc, const std::vector<ReportBlock>& blocks) {
  const size_t rc = std::min<size_t>(blocks.size(), 31);
  ByteWriter w;
  w.u8(static_cast<uint8_t>(0x80 | rc)).u8(201).be16(static_cast<uint16_t>(1 + rc * 6)).be32(sender_ssrc);
  for (size_t i = 0; i < rc; ++i) {
    const ReportBlock& b = blocks[i];
    w.be32(b.ssrc).be32(0).be32((b.roc & 0xFFFF) << 16 | b.max_seq).be32(0).be32(b.lsr).be32(b.dlsr);
  }
  return w.take();
}

Bytes compound_with_rr(uint32_t sender_ssrc, const Bytes& payload) {
  Bytes out = build_rr(sender_ssrc);
  out.insert(out.end(), payload.begin(), payload.end());
  return out;
}

std::vector<SrArrival> parse_sr_arrivals(const Bytes& data) {
  std::vector<SrArrival> out;
  size_t pos = 0;
  while (pos + 4 <= data.size()) {
    const uint8_t pt = data[pos + 1];
    const size_t len = (size_t(rd_be16(&data[pos + 2])) + 1) * 4;
    if (pos + len > data.size()) break;
    if (pt == 200 && len >= 28) {
      const uint32_t sec = rd_be32(&data[pos + 8]), frac = rd_be32(&data[pos + 12]);
      out.push_back({rd_be32(&data[pos + 4]), (sec & 0xFFFF) << 16 | (frac >> 16)});
    }
    pos += len;
  }
  return out;
}

}  // namespace iss::proto::rtcp
