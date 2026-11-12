#include "app/player.h"

#include <chrono>
#include <cstdio>
#include <cwctype>
#include <stdexcept>

#include "core/log.h"
#include "media/nalu.h"

namespace iss::app {
namespace {

Bytes read_whole_file(const std::wstring& path) {
  FILE* f = nullptr;
  if (_wfopen_s(&f, path.c_str(), L"rb") || !f) throw std::runtime_error("cannot open the clip");
  Bytes out;
  uint8_t buf[1 << 16];
  size_t n;
  while ((n = fread(buf, 1, sizeof(buf), f)) > 0) out.insert(out.end(), buf, buf + n);
  fclose(f);
  return out;
}

bool ends_with_ci(const std::wstring& s, const wchar_t* suffix) {
  std::wstring suf(suffix);
  if (s.size() < suf.size()) return false;
  for (size_t i = 0; i < suf.size(); ++i) {
    if (std::towlower(s[s.size() - suf.size() + i]) != suf[i]) return false;
  }
  return true;
}

bool is_slice(media::Codec c, const Bytes& nal) {
  if (nal.empty()) return false;
  if (c == media::Codec::Hevc) return media::hevc_nal_type(nal[0]) <= 31;
  int t = media::avc_nal_type(nal[0]);
  return t >= 1 && t <= 5;
}

}  // namespace

void FilePlayer::start(const Options& opt) {
  stop();
  opt_ = opt;
  codec_ = ends_with_ci(opt.path, L".h265") || ends_with_ci(opt.path, L".hevc") ? media::Codec::Hevc
                                                                                : media::Codec::H264;
  Bytes stream = read_whole_file(opt.path);
  extradata_.clear();
  nalus_.clear();
  bool seen[64] = {};
  for (Bytes& nal : media::split_annexb(stream)) {
    if (nal.empty()) continue;
    int t = codec_ == media::Codec::Hevc ? media::hevc_nal_type(nal[0]) : media::avc_nal_type(nal[0]);
    bool param = codec_ == media::Codec::Hevc ? (t >= 32 && t <= 34) : (t == 7 || t == 8);
    if (param) {
      if (!seen[t]) {
        seen[t] = true;
        extradata_.insert(extradata_.end(), {0, 0, 0, 1});
        extradata_.insert(extradata_.end(), nal.begin(), nal.end());
      }
      continue;
    }
    nalus_.push_back(std::move(nal));
  }
  if (extradata_.empty() || nalus_.empty()) throw std::runtime_error("no parameter sets / slices in the clip");
  log::info("play: {} NALUs ({})", nalus_.size(), codec_ == media::Codec::Hevc ? "HEVC" : "H.264");
  stop_ = false;
  thread_ = std::thread([this] { run(); });
}

void FilePlayer::stop() {
  stop_ = true;
  if (thread_.joinable()) thread_.join();
}

std::optional<media::VideoFrame> FilePlayer::take_frame() {
  std::lock_guard lk(mu_);
  std::optional<media::VideoFrame> out;
  out.swap(latest_);
  return out;
}

std::string FilePlayer::backend() const {
  std::lock_guard lk(mu_);
  return backend_;
}

std::string FilePlayer::error() const {
  std::lock_guard lk(mu_);
  return error_;
}

void FilePlayer::run() {
  using clock = std::chrono::steady_clock;
  const auto frame_period = std::chrono::duration_cast<clock::duration>(std::chrono::duration<double>(1.0 / opt_.fps));
  try {
    media::VideoDecoder dec;
    auto next = clock::now();
    while (!stop_) {
      // ループごとに開き直す。クリップはキーフレームで始まるので、新しいコンテキストなら
      // 問題なく最初からやり直せる。
      dec.open({codec_, opt_.prefer_hwaccel, opt_.adapter_index}, extradata_);
      std::vector<media::VideoFrame> frames;
      for (const Bytes& nal : nalus_) {
        if (stop_) break;
        frames.clear();
        dec.decode(nal, 0, frames);
        if (!frames.empty()) {
          decoded_ += frames.size();
          std::lock_guard lk(mu_);
          latest_ = std::move(frames.back());
          backend_ = dec.backend();
        }
        if (is_slice(codec_, nal)) {
          next += frame_period;
          std::this_thread::sleep_until(next);
        }
      }
      frames.clear();
      dec.flush(frames);
    }
  } catch (const std::exception& e) {
    log::error("play: {}", e.what());
    std::lock_guard lk(mu_);
    error_ = e.what();
  }
}

}  // namespace iss::app
