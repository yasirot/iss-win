// HEVCの帯 → 画面に出すピクチャ全体。
//
// Macは1枚のピクチャの帯（タイル。RTPタイムスタンプは共通）を上から下へ送る。
// 5Kでは帯ごとに前の帯から約5.2 ms遅れ、送るのは変化した帯だけ。デコードした
// 帯から順に表示すると、動いているウィンドウが帯の継ぎ目でずれて見える
// （ティアリング）。そのため1枚のピクチャの帯はまとめて渡す。渡すのは、最後の帯の
// あと、後のピクチャのパケットが届いたとき（受信途中の帯がある場合を除く）、または
// ピクチャの最新パケットを処理してから次の帯が始まらないまま`gap`が過ぎたとき。
// スレッドセーフではない。
#pragma once

#include <chrono>
#include <cstdint>
#include <map>
#include <vector>

#include "media/video_decoder.h"

namespace iss::session {

class PictureAssembler {
 public:
  using Clock = std::chrono::steady_clock;

  PictureAssembler(int strips, std::chrono::milliseconds gap) : strips_(strips), gap_(gap) {}

  // どの呼び出しも、いま表示する帯を古いピクチャから順に返す（ピクチャを
  // 組み立てている途中なら空）。
  std::vector<media::VideoFrame> add(media::VideoFrame f, Clock::time_point now);
  // ピクチャ`ts`のパケットを処理しているところで呼ぶ。`strip_pending`は、組み立て中の
  // ピクチャの帯に、一部だけ受け取ったものがあること。
  std::vector<media::VideoFrame> packet(uint32_t ts, Clock::time_point now, bool strip_pending);
  std::vector<media::VideoFrame> poll(Clock::time_point now);

  bool empty() const { return strips_in_.empty(); }
  uint32_t ts() const { return ts_; }

 private:
  void release(std::vector<media::VideoFrame>& out);

  int strips_;
  std::chrono::milliseconds gap_;
  std::map<int, media::VideoFrame> strips_in_;
  uint32_t ts_ = 0;
  Clock::time_point until_{};
};

}  // namespace iss::session
