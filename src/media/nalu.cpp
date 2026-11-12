#include "media/nalu.h"

#include <algorithm>
#include <string_view>

#include "media/bitstream.h"

namespace iss::media {

Bytes remove_emulation_prevention(const uint8_t* p, size_t n) {
  Bytes out;
  out.reserve(n);
  size_t i = 0;
  while (i < n) {
    if (i + 2 < n && p[i] == 0 && p[i + 1] == 0 && p[i + 2] == 3) {
      out.push_back(0);
      out.push_back(0);
      i += 3;
    } else {
      out.push_back(p[i++]);
    }
  }
  return out;
}

// ── HEVC ─────────────────────────────────────────────────────────────────

std::vector<Bytes> hevc_reassemble_group(const std::vector<Bytes>& payloads) {
  std::vector<Bytes> out;
  Bytes fu;
  bool fu_active = false;
  for (const Bytes& pay : payloads) {
    if (pay.size() < 2) continue;
    const int nt = hevc_nal_type(pay[0]);
    if (nt == HEVC_NAL_AGGREGATION) {
      // header(2) + DONL(2) + [size(2) + data]...
      size_t pos = 4;
      while (pos + 2 <= pay.size()) {
        size_t size = rd_be16(&pay[pos]);
        pos += 2;
        if (size == 0 || pos + size > pay.size()) break;
        out.emplace_back(pay.begin() + pos, pay.begin() + pos + size);
        pos += size;
      }
    } else if (nt == HEVC_NAL_FRAGMENTATION) {
      // header(2) + FU header(1) + DONL(2) + payload
      if (pay.size() < 6) continue;
      const uint8_t fu_hdr = pay[2];
      const bool start = fu_hdr & 0x80, end = fu_hdr & 0x40;
      if (start) {
        const uint8_t hdr0 = static_cast<uint8_t>((pay[0] & 0x81) | ((fu_hdr & 0x3F) << 1));
        fu.assign({hdr0, pay[1]});
        fu.insert(fu.end(), pay.begin() + 5, pay.end());
        fu_active = true;
      } else if (fu_active) {
        fu.insert(fu.end(), pay.begin() + 5, pay.end());
        if (end) {
          out.push_back(std::move(fu));
          fu.clear();
          fu_active = false;
        }
      }
    } else {
      // 単独のNAL。ヘッダーの直後に2バイトのDONLが付く。
      if (pay.size() < 4) continue;
      Bytes nal(pay.begin(), pay.begin() + 2);
      nal.insert(nal.end(), pay.begin() + 4, pay.end());
      out.push_back(std::move(nal));
    }
  }
  return out;
}

std::optional<uint16_t> hevc_payload_donl(const Bytes& pay) {
  if (pay.size() < 2) return std::nullopt;
  if (hevc_nal_type(pay[0]) == HEVC_NAL_FRAGMENTATION) {
    if (pay.size() >= 5) return rd_be16(&pay[3]);
  } else if (pay.size() >= 4) {
    return rd_be16(&pay[2]);
  }
  return std::nullopt;
}

std::optional<uint16_t> hevc_first_donl(const std::vector<Bytes>& payloads) {
  for (const Bytes& pay : payloads) {
    if (auto d = hevc_payload_donl(pay)) return d;
  }
  return std::nullopt;
}

// H.265 §7.3.2.2のconformance windowまでを読む。profile_tier_levelは§7.3.3による。
std::optional<HevcSpsInfo> parse_hevc_sps(const Bytes& nal) {
  if (nal.size() < 4 || hevc_nal_type(nal[0]) != HEVC_NAL_SPS) return std::nullopt;
  const Bytes rbsp = remove_emulation_prevention(nal.data() + 2, nal.size() - 2);
  BitReader br(rbsp);
  HevcSpsInfo s;
  br.read(4);  // sps_video_parameter_set_id
  const int sub_layers = static_cast<int>(br.read(3));  // sps_max_sub_layers_minus1
  br.read(1);  // sps_temporal_id_nesting_flag
  br.read(88);  // general_profile_spaceからgeneral_inbld/reservedのフラグまで
  s.level_idc = static_cast<int>(br.read(8));
  bool profile_present[8] = {}, level_present[8] = {};
  for (int i = 0; i < sub_layers; ++i) {
    profile_present[i] = br.read1();
    level_present[i] = br.read1();
  }
  if (sub_layers > 0) br.read(2 * (8 - sub_layers));  // reserved_zero_2bits
  for (int i = 0; i < sub_layers; ++i) {
    if (profile_present[i]) br.read(88);
    if (level_present[i]) br.read(8);
  }
  br.read_ue();  // sps_seq_parameter_set_id
  s.chroma_format_idc = static_cast<int>(br.read_ue());
  if (s.chroma_format_idc == 3) br.read1();  // separate_colour_plane_flag
  s.width = static_cast<int>(br.read_ue());
  s.height = static_cast<int>(br.read_ue());
  if (br.read1()) {  // conformance_window_flag。オフセットはクロマのサンプル単位
    const int sub_w = s.chroma_format_idc == 1 || s.chroma_format_idc == 2 ? 2 : 1;
    const int sub_h = s.chroma_format_idc == 1 ? 2 : 1;
    const auto left = br.read_ue(), right = br.read_ue(), top = br.read_ue(), bottom = br.read_ue();
    s.width -= static_cast<int>(sub_w * (left + right));
    s.height -= static_cast<int>(sub_h * (top + bottom));
  }
  if (s.width <= 0 || s.height <= 0) return std::nullopt;
  return s;
}

// ── H.264 ────────────────────────────────────────────────────────────────

std::vector<Bytes> avc_reassemble(const std::vector<Bytes>& payloads) {
  std::vector<Bytes> out;
  Bytes fu;
  bool fu_active = false;
  for (const Bytes& pay : payloads) {
    if (pay.empty()) continue;
    const uint8_t b0 = pay[0];
    if (b0 == APPLE_AVC_CONFIG_MARKER) continue;
    const int t = avc_nal_type(b0);
    if (t == AVC_NAL_FU_A || t == AVC_NAL_FU_B) {
      const size_t data_off = 2 + (t == AVC_NAL_FU_B ? 2 : 0);
      if (pay.size() < data_off) continue;
      const uint8_t fu_hdr = pay[1];
      const bool start = fu_hdr & 0x80, end = fu_hdr & 0x40;
      if (start) {
        // forbidden_zeroとnal_ref_idcはindicatorから、typeはFUヘッダーから取る。
        fu.assign({static_cast<uint8_t>((b0 & 0xE0) | (fu_hdr & 0x1F))});
        fu.insert(fu.end(), pay.begin() + data_off, pay.end());
        fu_active = true;
      } else if (fu_active) {
        fu.insert(fu.end(), pay.begin() + data_off, pay.end());
        if (end) {
          out.push_back(std::move(fu));
          fu.clear();
          fu_active = false;
        }
      }
    } else if (t == AVC_NAL_STAP_A) {
      // RFC 6184どおりのindicator(1) + [size(2) + NAL]...（2台目のディスプレイの
      // ストリームがこれで、SPS + PPS + キーフレームのスライスが入る）か、
      // indicatorの後ろにDON(2)が付いた形。sizeを足すとパケット長にちょうど
      // 一致するほうを正しいレイアウトとする。
      auto split = [&](size_t pos, std::vector<Bytes>* nals) {
        while (pos + 2 <= pay.size()) {
          const size_t size = rd_be16(&pay[pos]);
          pos += 2;
          if (size == 0 || pos + size > pay.size()) return false;
          if (nals) nals->emplace_back(pay.begin() + pos, pay.begin() + pos + size);
          pos += size;
        }
        return pos == pay.size();
      };
      split(split(1, nullptr) ? 1 : 3, &out);
    } else if (t >= 1 && t <= 23) {
      // 単独のNAL。AppleはDONなしで送ってくる。
      if (pay.size() < 2) continue;
      out.push_back(pay);
    }
  }
  return out;
}

bool avc_payload_starts_keyframe(const Bytes& pay) {
  if (pay.size() < 2 || pay[0] == APPLE_AVC_CONFIG_MARKER) return false;
  const int t = avc_nal_type(pay[0]);
  if (t == AVC_NAL_FU_A) {
    if (!(pay[1] & 0x80)) return false;
    // スライスヘッダーの先頭。組み立て直したNALヘッダーに、先頭の数バイトを続ける。
    Bytes head = {static_cast<uint8_t>((pay[0] & 0xE0) | (pay[1] & 0x1F))};
    head.insert(head.end(), pay.begin() + 2, pay.begin() + static_cast<std::ptrdiff_t>(std::min<size_t>(pay.size(), 18)));
    return avc_nal_is_keyframe(head);
  }
  if (t == AVC_NAL_STAP_A) {
    const std::vector<Bytes> nals = avc_reassemble({pay});
    return std::any_of(nals.begin(), nals.end(), [](const Bytes& nal) { return avc_nal_is_keyframe(nal); });
  }
  return t >= 1 && t <= 23 && avc_nal_is_keyframe(pay);
}

namespace {

// Pythonのbytes.split(b"\x00\x00\x00\x01")と同じ。
std::vector<std::pair<size_t, size_t>> split_start_codes(const Bytes& au) {
  std::vector<std::pair<size_t, size_t>> parts;
  static const uint8_t kSc[4] = {0, 0, 0, 1};
  size_t begin = 0;
  for (;;) {
    auto it = std::search(au.begin() + begin, au.end(), kSc, kSc + 4);
    size_t at = static_cast<size_t>(it - au.begin());
    parts.emplace_back(begin, at - begin);
    if (it == au.end()) break;
    begin = at + 4;
  }
  return parts;
}

}  // namespace

bool avc_au_is_keyframe(const Bytes& au) {
  for (auto [off, len] : split_start_codes(au)) {
    if (len < 2) continue;
    const uint8_t* nal = au.data() + off;
    const int t = avc_nal_type(nal[0]);
    if (t == AVC_NAL_SLICE_IDR) return true;
    if (t == AVC_NAL_SLICE_NONIDR) {
      Bytes rbsp = remove_emulation_prevention(nal + 1, len - 1);
      BitReader br(rbsp);
      br.read_ue();                      // first_mb_in_slice
      uint64_t slice_type = br.read_ue();
      if (slice_type == 2 || slice_type == 7) return true;  // I / Iだけのピクチャ
    }
  }
  return false;
}

bool avc_au_has_sps(const Bytes& au) {
  for (auto [off, len] : split_start_codes(au)) {
    if (len && avc_nal_type(au[off]) == AVC_NAL_SPS) return true;
  }
  return false;
}

std::optional<AvcConfig> parse_avc_config(const Bytes& payload) {
  auto find = [&](std::string_view tag, size_t from) -> size_t {
    if (from > payload.size()) return SIZE_MAX;
    auto it = std::search(payload.begin() + from, payload.end(), tag.begin(), tag.end());
    return it == payload.end() ? SIZE_MAX : static_cast<size_t>(it - payload.begin());
  };
  // SPS/PPSのデータにたまたま含まれる"avcC"をボックスと取り違えないよう、
  // avc1サンプルエントリの位置から探す。
  size_t a1 = find("avc1", 0);
  size_t idx = find("avcC", a1 == SIZE_MAX ? 0 : a1);
  if (idx == SIZE_MAX) return std::nullopt;
  size_t p = idx + 4;
  const size_t n = payload.size();
  if (p + 6 > n) return std::nullopt;
  const int num_sps = payload[p + 5] & 0x1F;
  p += 6;
  std::optional<Bytes> sps, pps;
  for (int i = 0; i < num_sps; ++i) {
    if (p + 2 > n) return std::nullopt;
    size_t len = rd_be16(&payload[p]);
    p += 2;
    if (p + len > n) return std::nullopt;
    if (!sps) sps = Bytes(payload.begin() + p, payload.begin() + p + len);
    p += len;
  }
  if (p + 1 > n) return std::nullopt;
  const int num_pps = payload[p++];
  for (int i = 0; i < num_pps; ++i) {
    if (p + 2 > n) return std::nullopt;
    size_t len = rd_be16(&payload[p]);
    p += 2;
    if (p + len > n) return std::nullopt;
    if (!pps) pps = Bytes(payload.begin() + p, payload.begin() + p + len);
    p += len;
  }
  if (!sps || !pps) return std::nullopt;
  return AvcConfig{std::move(*sps), std::move(*pps)};
}

Bytes patch_avc_sps_dpb(const Bytes& sps) {
  if (sps.size() < 4 || avc_nal_type(sps[0]) != AVC_NAL_SPS) return sps;
  std::vector<uint8_t> bits;  // sps[1:]の1ビットを1要素にする
  bits.reserve((sps.size() - 1) * 8);
  for (size_t i = 1; i < sps.size(); ++i) {
    for (int b = 7; b >= 0; --b) bits.push_back((sps[i] >> b) & 1);
  }
  struct Truncated {};
  size_t pos = 0;
  auto u = [&](int n) {
    uint32_t v = 0;
    for (int i = 0; i < n; ++i) {
      if (pos >= bits.size()) throw Truncated{};
      v = v << 1 | bits[pos++];
    }
    return v;
  };
  // 値を返す。`start` / `end` にはその値のビットの範囲が入る。
  auto ue = [&](size_t* start = nullptr, size_t* end = nullptr) {
    if (start) *start = pos;
    int zeros = 0;
    for (; pos < bits.size() && bits[pos] == 0; ++pos) ++zeros;
    if (pos >= bits.size() || zeros > 31) throw Truncated{};
    ++pos;
    const uint32_t v = (1u << zeros) - 1 + (zeros ? u(zeros) : 0);
    if (end) *end = pos;
    return v;
  };

  try {
    const uint32_t profile = u(8);
    u(8);  // constraintのフラグ
    const size_t level_start = pos;
    u(8);  // level_idc
    ue();  // seq_parameter_set_id
    static constexpr uint32_t kHighProfiles[] = {100, 110, 122, 244, 44, 83, 86, 118, 128, 138, 139, 134, 135};
    if (std::find(std::begin(kHighProfiles), std::end(kHighProfiles), profile) != std::end(kHighProfiles)) {
      if (ue() == 3) u(1);  // chroma_format_idc, separate_colour_plane_flag
      ue();                 // bit_depth_luma_minus8
      ue();                 // bit_depth_chroma_minus8
      u(1);                 // qpprime_y_zero_transform_bypass_flag
      if (u(1)) return sps;  // seq_scaling_matrix_present_flag。このときは手を付けない
    }
    ue();  // log2_max_frame_num_minus4
    const uint32_t poc_type = ue();
    if (poc_type == 0) {
      ue();  // log2_max_pic_order_cnt_lsb_minus4
    } else if (poc_type == 1) {
      u(1);
      ue();
      ue();
      for (uint32_t i = 0, n = ue(); i < n; ++i) ue();
    }
    size_t ref_start = 0, ref_end = 0;
    if (ue(&ref_start, &ref_end) < 16) {
      static constexpr uint8_t kUe16[] = {0, 0, 0, 0, 1, 0, 0, 0, 1};  // ue(16) = 000010001
      bits.erase(bits.begin() + static_cast<std::ptrdiff_t>(ref_start), bits.begin() + static_cast<std::ptrdiff_t>(ref_end));
      bits.insert(bits.begin() + static_cast<std::ptrdiff_t>(ref_start), std::begin(kUe16), std::end(kUe16));
    }
    for (int i = 0; i < 8; ++i) bits[level_start + i] = (60 >> (7 - i)) & 1;  // レベル6.0
  } catch (const Truncated&) {
    return sps;
  }

  Bytes out{sps[0]};
  for (size_t i = 0; i < bits.size(); i += 8) {
    uint8_t byte = 0;
    for (size_t j = 0; j < 8; ++j) byte = static_cast<uint8_t>(byte << 1 | (i + j < bits.size() ? bits[i + j] : 0));
    out.push_back(byte);
  }
  return out;
}

}  // namespace iss::media
