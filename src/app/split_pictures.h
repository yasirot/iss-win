// --perf用。ストリップが2回以上のPresentに分かれて画面に出たHEVCピクチャを数える。
// そうしたピクチャでは、動いているウィンドウがストリップの継ぎ目でずれて見える。
#pragma once

#include <cstdint>
#include <map>
#include <utility>

namespace iss {

class SplitPictures {
 public:
  // ピクチャ`rtp_ts`のストリップを、`present`番目のPresent用にアップロードした。
  void strip(uint32_t rtp_ts, uint64_t present) {
    auto [it, fresh] = seen_.try_emplace(rtp_ts, Picture{present});
    Picture& p = it->second;
    if (!fresh) {
      if (++p.strips == 2) ++multi_;
      if (present != p.first_present && !p.split) {
        p.split = true;
        ++split_;
      }
    }
    // ピクチャは1秒ほど覚えておけば足りる。同じピクチャのストリップは約20 ms以内に届く。
    for (auto i = seen_.begin(); i != seen_.end();) {
      i = i->second.first_present + kKeepPresents < present ? seen_.erase(i) : std::next(i);
    }
  }

  // 前回の呼び出しからの（分かれたピクチャ数, ストリップが2本以上のピクチャ数）。
  std::pair<uint64_t, uint64_t> take() {
    const std::pair out{split_, multi_};
    split_ = multi_ = 0;
    return out;
  }

 private:
  static constexpr uint64_t kKeepPresents = 120;
  struct Picture {
    uint64_t first_present;
    int strips = 1;
    bool split = false;
  };
  std::map<uint32_t, Picture> seen_;
  uint64_t split_ = 0, multi_ = 0;
};

}  // namespace iss
