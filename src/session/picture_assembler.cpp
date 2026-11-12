#include "session/picture_assembler.h"

#include <algorithm>

namespace iss::session {

void PictureAssembler::release(std::vector<media::VideoFrame>& out) {
  for (auto& [strip, f] : strips_in_) out.push_back(std::move(f));
  strips_in_.clear();
}

std::vector<media::VideoFrame> PictureAssembler::add(media::VideoFrame f, Clock::time_point now) {
  std::vector<media::VideoFrame> out;
  if (!strips_in_.empty() && f.rtp_ts != ts_) release(out);
  if (strips_in_.empty()) until_ = {};
  ts_ = f.rtp_ts;
  until_ = std::max(until_, now + gap_);
  const int strip = f.tile;
  strips_in_[strip] = std::move(f);
  if (strip >= strips_ - 1) release(out);  // 上から下へ届くので、最後の帯のあとには何も来ない
  return out;
}

std::vector<media::VideoFrame> PictureAssembler::packet(uint32_t ts, Clock::time_point now, bool strip_pending) {
  std::vector<media::VideoFrame> out;
  if (strips_in_.empty()) return out;
  if (ts == ts_) {
    until_ = std::max(until_, now + gap_);
  } else if (static_cast<int32_t>(ts - ts_) > 0 && !strip_pending) {
    release(out);
  }
  return out;
}

std::vector<media::VideoFrame> PictureAssembler::poll(Clock::time_point now) {
  std::vector<media::VideoFrame> out;
  if (!strips_in_.empty() && now >= until_) release(out);
  return out;
}

}  // namespace iss::session
