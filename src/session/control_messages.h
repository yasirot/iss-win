// ホストが暗号化された制御チャネルで送ってくるFramebufferUpdate（session.pyの
// _handle_fbu / _handle_cursor_rectの移植）。ピクセルはUDPで届くので、ここに
// 来る矩形は疑似エンコーディングになる。
//
//   1104   カーソル。u32のcache_id、u32のcomp_sizeのあとに（comp_size > 0なら）
//          sync flushで終わるzlibストリームが続き、w*hのBGRA + w*hのアルファマスクが
//          入っている。comp_size == 0なら、以前cache_idで送った形をもう一度選ぶ。
//          矩形ヘッダの4つのu16はホットスポットのx/y、幅、高さ。
//   0x451  AppleDisplayLayout。u16の長さ + ペイロード（スケール後とバッキングの
//          サイズ、ディスプレイごとの矩形）。
//   1010 1011 1107 1109 1110 0x3ea 0x3f2 0x3f3 0x453 0x455 0x456:
//          u16の長さ + ペイロード。読み飛ばす。
// それ以外のエンコーディングが来たらそこで読むのをやめる（ペイロードのサイズが分からないため）。
#pragma once

#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

#include "core/bytes.h"
#include "proto/rfb.h"

namespace iss::session {

// ホストのカーソル画像1つ。ストレート（乗算済みでない）BGRAで、アルファはマスクから
// 取る。単位はキャンバス（バッキング）のピクセル。
struct CursorShape {
  int width = 0;
  int height = 0;
  int hot_x = 0;
  int hot_y = 0;
  Bytes bgra;
};
using CursorRef = std::shared_ptr<const CursorShape>;

// ホストのキャッシュIDで引くカーソルの形（ホストはcomp_size 0で選び直す）。
class CursorCache {
 public:
  CursorRef get(uint32_t id) const;
  void put(uint32_t id, CursorRef shape);

 private:
  static constexpr size_t kMax = 64;  // Appleが使うのは約16
  std::map<uint32_t, CursorRef> shapes_;
  std::deque<uint32_t> order_;
};

struct DisplayLayoutInfo {
  int scaled_w = 0, scaled_h = 0;    // ポイント
  int backing_w = 0, backing_h = 0;  // ピクセル
  size_t displays = 0;
  std::vector<rfb::DisplayRect> rects;  // バッキングキャンバス上の各ディスプレイ
};

// 標準モードの更新に含まれるピクセルの矩形。メッセージの中を指すビュー。
struct PixelRect {
  int x = 0, y = 0, w = 0, h = 0;
  int32_t encoding = 0;
  const uint8_t* data = nullptr;  // 12バイトの矩形ヘッダのあとのペイロード
  size_t size = 0;
};

struct FbuEvents {
  // カーソルの矩形ごとに、順に形かnullを入れる。nullは形を受け取っていない
  // キャッシュIDで、既定の矢印として表示する（Pythonクライアントと同じ）。
  std::vector<CursorRef> cursors;
  std::optional<DisplayLayoutInfo> layout;
  bool truncated = false;  // 途中でバイトが尽きたか、未知のエンコーディングが来た
  std::vector<int32_t> encodings;  // 全矩形のエンコーディングを順に（診断用）
  // 標準モードのみ。ピクセルの矩形（順番どおり）と、DesktopSize（-223）。
  std::vector<PixelRect> pixels;
  std::optional<std::pair<int, int>> desktop_size;
};

// `framebuffer`は標準モードのセッションであること。標準モードでは更新にピクセルの
// 矩形（Raw、CopyRect、zlib、ZRLE、Appleの1000-1002と1011）も入っている。
// メディアの経路では1002 / 1011がピクセルになることはなく、長さが前に付いた
// データとして読み飛ばす。
FbuEvents parse_fbu(const Bytes& msg, CursorCache& cache, bool framebuffer = false);

// 標準モードで、`p`にあるFramebufferUpdateの長さを返す（矩形は複数のレコードに
// またがることがある）。0ならバイトがまだ足りない。kUnknownLengthならサイズの
// 分からないエンコーディングがある（更新の区切りが決められない）。
inline constexpr size_t kUnknownLength = static_cast<size_t>(-1);
size_t fbu_length(const uint8_t* p, size_t n);

}  // namespace iss::session
