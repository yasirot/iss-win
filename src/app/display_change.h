// 「Macがこのディスプレイを作り直している」という表示をビューに重ねる時期を決める。
// Win32を呼ばないので、テストから動かせる。
#pragma once

#include <chrono>
#include <cstdint>
#include <cstdlib>

namespace iss::app {

// 解像度の要求（またはMac側での変更）を受けると、Macは仮想ディスプレイを作り直して
// エンコーダーを再起動する。その間の約2秒は古い映像が残る。表示は要求の時点から、
// Macが答えたサイズの映像が届くまで出す。古いストリームの映像とはサイズだけで
// 見分ける。
class DisplayChange {
 public:
  using Clock = std::chrono::steady_clock;
  static constexpr auto kTimeout = std::chrono::seconds(10);
  static constexpr int kSizeSlackPx = 16;  // デコード後のサイズはクロップで数行減ることがある
  static constexpr int kTilePaddingMax = 64;  // タイルがディスプレイの下端を越えてよい行数（1CTB分）

  bool active() const { return active_; }
  Clock::time_point since() const { return since_; }

  // 要求を送った。`layouts`はそのときのセッションのlayouts_received()。
  void requested(Clock::time_point now, uint64_t layouts) {
    if (!active_) since_ = now;
    active_ = true;
    layouts_at_start_ = layouts;
    expect_w_ = expect_h_ = 0;
  }

  // 描画ループで毎回呼ぶ。引数は最新のレイアウトでのこのディスプレイのピクセルサイズと、
  // 届いたレイアウトの数。こちらが要求していないのにMacがディスプレイを変えた（Macの
  // ディスプレイ設定から）ときにtrueを返す。その変更は今始まり、答えはもう届いている。
  bool on_layout(Clock::time_point now, uint64_t layouts, int w, int h) {
    bool started = false;
    if (!active_ && last_w_ > 0 && (w != last_w_ || h != last_h_)) {
      active_ = true;
      since_ = now;
      layouts_at_start_ = layouts - 1;
      expect_w_ = expect_h_ = 0;
      started = true;
    }
    last_w_ = w;
    last_h_ = h;
    if (active_ && expect_w_ == 0 && layouts > layouts_at_start_) {
      expect_w_ = w;
      expect_h_ = h;
    }
    return started;
  }

  // 映像を1枚表示した。それで変更が終わるときにtrue。`tiles`（HEVC）があるときは、
  // ディスプレイを縦に積んだその数のストリップの1本で、最後の1本は下端を越えて
  // パディングされている。
  bool on_frame(int w, int h, int tiles = 1) {
    if (!active_ || expect_w_ == 0 || std::abs(w - expect_w_) > kSizeSlackPx) return false;
    const int rows = h * tiles;
    const bool fits = tiles > 1 ? rows >= expect_h_ && rows - expect_h_ < tiles * kTilePaddingMax
                                : std::abs(rows - expect_h_) <= kSizeSlackPx;
    if (!fits) return false;
    active_ = false;
    return true;
  }

  // 変更を終わらせるときにtrue。時間内に新しいサイズの映像が来なかった（Macが要求を
  // 無視したか、ストリームが戻らなかった）場合。
  bool expired(Clock::time_point now) {
    if (!active_ || now - since_ < kTimeout) return false;
    active_ = false;
    return true;
  }

 private:
  bool active_ = false;
  Clock::time_point since_{};
  uint64_t layouts_at_start_ = 0;
  int expect_w_ = 0, expect_h_ = 0;  // 0: Macがまだ答えていない
  int last_w_ = 0, last_h_ = 0;      // 最後に見たレイアウトでの値
};

}  // namespace iss::app
