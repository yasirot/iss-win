#include "media/hevc_refs.h"

#include <algorithm>
#include <climits>
#include <tuple>

#include "media/bitstream.h"
#include "media/nalu.h"

namespace iss::media {
namespace {

int ceil_log2(size_t n) {
  int bits = 0;
  while ((size_t{1} << bits) < n) ++bits;
  return bits;
}

// st_ref_pic_set（H.265 §7.3.7、導出は§7.4.8）。
HevcStRps read_st_rps(BitReader& b, size_t idx, const std::vector<HevcStRps>& sets) {
  HevcStRps out;
  if (idx != 0 && b.read1()) {  // inter_ref_pic_set_prediction_flag
    const size_t delta_idx = idx == sets.size() ? b.read_ue() + 1 : 1;
    const bool sign = b.read1();
    const int delta_rps = (sign ? -1 : 1) * static_cast<int>(b.read_ue() + 1);
    if (delta_idx > idx) return out;
    const HevcStRps& ref = sets[idx - delta_idx];
    const size_t nn = ref.s0.size(), n = nn + ref.s1.size();
    std::vector<bool> used(n + 1), use(n + 1);
    for (size_t j = 0; j <= n; ++j) {
      used[j] = b.read1();
      use[j] = used[j] || b.read1();
    }
    for (size_t j = ref.s1.size(); j-- > 0;) {
      const int d = ref.s1[j].first + delta_rps;
      if (d < 0 && use[nn + j]) out.s0.push_back({d, used[nn + j]});
    }
    if (delta_rps < 0 && use[n]) out.s0.push_back({delta_rps, used[n]});
    for (size_t j = 0; j < nn; ++j) {
      const int d = ref.s0[j].first + delta_rps;
      if (d < 0 && use[j]) out.s0.push_back({d, used[j]});
    }
    for (size_t j = nn; j-- > 0;) {
      const int d = ref.s0[j].first + delta_rps;
      if (d > 0 && use[j]) out.s1.push_back({d, used[j]});
    }
    if (delta_rps > 0 && use[n]) out.s1.push_back({delta_rps, used[n]});
    for (size_t j = 0; j < ref.s1.size(); ++j) {
      const int d = ref.s1[j].first + delta_rps;
      if (d > 0 && use[nn + j]) out.s1.push_back({d, used[nn + j]});
    }
    return out;
  }
  const uint64_t neg = b.read_ue(), pos = b.read_ue();
  if (neg > 16 || pos > 16) return out;
  int d = 0;
  for (uint64_t i = 0; i < neg; ++i) {
    d -= static_cast<int>(b.read_ue() + 1);
    out.s0.push_back({d, b.read1() != 0});
  }
  d = 0;
  for (uint64_t i = 0; i < pos; ++i) {
    d += static_cast<int>(b.read_ue() + 1);
    out.s1.push_back({d, b.read1() != 0});
  }
  return out;
}

}  // namespace

void HevcRefTracker::reset() {
  prev_msb_ = prev_lsb_ = 0;
  seen_idr_ = false;
  clean_.clear();
}

bool HevcRefTracker::set_sps(const Bytes& nal) {
  sps_ok_ = false;
  if (nal.size() < 4 || hevc_nal_type(nal[0]) != HEVC_NAL_SPS) return false;
  const Bytes rbsp = remove_emulation_prevention(nal.data() + 2, nal.size() - 2);
  BitReader b(rbsp);
  b.read(4);
  const int sub_layers = static_cast<int>(b.read(3));
  b.read1();
  b.read(96);  // generalのprofile / tier / level
  bool profile[8] = {}, level[8] = {};
  for (int i = 0; i < sub_layers; ++i) {
    profile[i] = b.read1();
    level[i] = b.read1();
  }
  if (sub_layers > 0) b.read(2 * (8 - sub_layers));
  for (int i = 0; i < sub_layers; ++i) {
    if (profile[i]) b.read(88);
    if (level[i]) b.read(8);
  }
  b.read_ue();
  const uint64_t chroma = b.read_ue();
  separate_colour_ = chroma == 3 && b.read1();
  width_ = static_cast<int>(b.read_ue());
  height_ = static_cast<int>(b.read_ue());
  if (b.read1()) {
    for (int i = 0; i < 4; ++i) b.read_ue();
  }
  b.read_ue();
  b.read_ue();
  log2_poc_ = static_cast<int>(b.read_ue()) + 4;
  const bool ordering_all = b.read1();
  for (int i = ordering_all ? 0 : sub_layers; i <= sub_layers; ++i) {
    b.read_ue();
    b.read_ue();
    b.read_ue();
  }
  const int min_cb = static_cast<int>(b.read_ue()) + 3;
  ctb_log2_ = min_cb + static_cast<int>(b.read_ue());
  for (int i = 0; i < 4; ++i) b.read_ue();
  if (b.read1() && b.read1()) return false;  // scaling list。Appleのストリームには出てこない
  b.read1();  // amp
  b.read1();  // sao
  if (b.read1()) {  // pcm
    b.read(8);
    b.read_ue();
    b.read_ue();
    b.read1();
  }
  const uint64_t n = b.read_ue();
  if (n > 64 || log2_poc_ > 16) return false;
  sets_.clear();
  for (size_t i = 0; i < n; ++i) sets_.push_back(read_st_rps(b, i, sets_));
  lt_sps_.clear();
  lt_present_ = b.read1();
  if (lt_present_) {
    const uint64_t m = b.read_ue();
    if (m > 32) return false;
    for (uint64_t i = 0; i < m; ++i) {
      const int lsb = static_cast<int>(b.read(log2_poc_));
      lt_sps_.push_back({lsb, b.read1() != 0});
    }
  }
  sps_ok_ = width_ > 0 && height_ > 0;
  return sps_ok_;
}

bool HevcRefTracker::set_pps(const Bytes& nal) {
  pps_ok_ = false;
  if (nal.size() < 3 || hevc_nal_type(nal[0]) != HEVC_NAL_PPS) return false;
  const Bytes rbsp = remove_emulation_prevention(nal.data() + 2, nal.size() - 2);
  BitReader b(rbsp);
  b.read_ue();
  b.read_ue();
  dependent_slices_ = b.read1();
  output_flag_ = b.read1();
  extra_bits_ = static_cast<int>(b.read(3));
  pps_ok_ = true;
  return true;
}

std::optional<HevcRefTracker::Picture> HevcRefTracker::add(const Bytes& nal) {
  if (!ready() || nal.size() < 3) return std::nullopt;
  const int t = hevc_nal_type(nal[0]);
  if (t > 31) return std::nullopt;
  const Bytes rbsp = remove_emulation_prevention(nal.data() + 2, std::min<size_t>(nal.size() - 2, 96));
  BitReader b(rbsp);
  if (!b.read1()) return std::nullopt;  // first_slice_segment_in_pic_flag
  if (hevc_is_irap(t) || t == 22 || t == 23) b.read1();
  b.read_ue();
  b.read(extra_bits_);
  const uint64_t slice_type = b.read_ue();
  if (output_flag_) b.read1();
  if (separate_colour_) b.read(2);

  Picture pic;
  if (t == 19 || t == 20) {  // IDR。POCは0、DPBは空
    pic.idr = pic.clean = true;
    prev_msb_ = prev_lsb_ = 0;
    seen_idr_ = true;
    clean_ = {0};
    return pic;
  }
  const int max_lsb = 1 << log2_poc_;
  const int lsb = static_cast<int>(b.read(log2_poc_));
  int msb = prev_msb_;
  if (lsb < prev_lsb_ && prev_lsb_ - lsb >= max_lsb / 2) msb += max_lsb;
  if (lsb > prev_lsb_ && lsb - prev_lsb_ > max_lsb / 2) msb -= max_lsb;
  pic.poc = msb + lsb;
  const int temporal_id = (nal[1] & 7) - 1;
  const bool sub_layer_non_ref = t <= 14 && t % 2 == 0;
  if (temporal_id == 0 && !sub_layer_non_ref && !(t >= 6 && t <= 9)) {
    prev_msb_ = msb;
    prev_lsb_ = lsb;
  }

  HevcStRps rps;
  if (!b.read1()) {
    rps = read_st_rps(b, sets_.size(), sets_);
  } else if (!sets_.empty()) {
    const size_t idx = sets_.size() > 1 ? b.read(ceil_log2(sets_.size())) : 0;
    if (idx >= sets_.size()) return std::nullopt;
    rps = sets_[idx];
  }
  std::set<int> dpb;
  for (const auto* list : {&rps.s0, &rps.s1}) {
    for (const auto& [delta, used] : *list) {
      dpb.insert(pic.poc + delta);
      if (used && slice_type != 2) pic.used.push_back(pic.poc + delta);
    }
  }
  if (lt_present_) {
    const uint64_t n_sps = lt_sps_.empty() ? 0 : b.read_ue();
    const uint64_t n_pics = b.read_ue();
    if (n_sps + n_pics > 32) return std::nullopt;
    int msb_cycle = 0;
    for (uint64_t i = 0; i < n_sps + n_pics; ++i) {
      int lt_lsb = 0;
      bool used = false;
      if (i < n_sps) {
        const size_t idx = lt_sps_.size() > 1 ? b.read(ceil_log2(lt_sps_.size())) : 0;
        if (idx >= lt_sps_.size()) return std::nullopt;
        std::tie(lt_lsb, used) = lt_sps_[idx];
      } else {
        lt_lsb = static_cast<int>(b.read(log2_poc_));
        used = b.read1();
      }
      std::optional<int> poc;
      if (b.read1()) {  // delta_poc_msb_present_flag
        const int cycle = static_cast<int>(b.read_ue());
        msb_cycle = i == 0 || i == n_sps ? cycle : msb_cycle + cycle;
        poc = pic.poc - msb_cycle * max_lsb - (lsb - lt_lsb);
      } else {
        // LSBだけが来る。DPBの中でそのLSBを持つピクチャを使う。
        for (int p : clean_) {
          if ((p & (max_lsb - 1)) == lt_lsb) poc = p;
        }
      }
      if (poc) dpb.insert(*poc);
      if (used && slice_type != 2) pic.used.push_back(poc.value_or(INT_MIN));
    }
  }

  pic.clean = seen_idr_ && std::all_of(pic.used.begin(), pic.used.end(), [&](int p) { return clean_.count(p) > 0; });
  std::erase_if(clean_, [&](int p) { return !dpb.count(p); });
  if (pic.clean) clean_.insert(pic.poc);
  return pic;
}

}  // namespace iss::media
