// ローカルファイルの再生（--play）。Annex-BのH.264/HEVCエレメンタリストリームを
// ワーカースレッドで一定のフレームレートでループしながらデコードし、最新のフレームを
// 描画スレッドに渡す。ネットワークのセッションなしでデコード → アップロード → 描画を
// 試すためのもの。
#pragma once

#include <atomic>
#include <mutex>
#include <optional>
#include <string>
#include <thread>

#include "media/video_decoder.h"

namespace iss::app {

class FilePlayer {
 public:
  struct Options {
    std::wstring path;
    int adapter_index = -1;
    bool prefer_hwaccel = true;
    double fps = 30.0;
  };

  ~FilePlayer() { stop(); }

  // ファイルを読めないか、デコードできないときはstd::runtime_errorを投げる。
  void start(const Options& opt);
  void stop();

  // 前回の呼び出し以降の最新のデコード済みフレーム。なければ空。
  std::optional<media::VideoFrame> take_frame();
  uint64_t frames_decoded() const { return decoded_; }
  std::string backend() const;
  std::string error() const;

 private:
  void run();

  Options opt_;
  media::Codec codec_ = media::Codec::Hevc;
  Bytes extradata_;
  std::vector<Bytes> nalus_;
  std::thread thread_;
  std::atomic<bool> stop_{false};
  std::atomic<uint64_t> decoded_{0};
  mutable std::mutex mu_;
  std::optional<media::VideoFrame> latest_;
  std::string backend_ = "-";
  std::string error_;
};

}  // namespace iss::app
