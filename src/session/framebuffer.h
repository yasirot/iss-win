// 標準モード（メディアの経路を使わない画面共有）。Macの画面は制御チャネル上の
// フレームバッファ更新の矩形として届き、ここでUI用の32ビットのキャンバス
// （メモリ上はBGRA、アルファ255）として持つ。
//
// ピクセルのエンコーディング。RawとCopyRect以外は、u32の長さ + zlibストリームの
// 一部で、zlibストリームは接続している間ずっと続き、各部分はsync flushで終わる。
//   0     Raw: サーバーの形式の32ビットピクセル（BGRX、リトルエンディアン）
//   1     CopyRect: コピー元のx、y（u16）
//   6     zlib: 32ビットのBGRX
//   16    ZRLE（RFC 6143）: 64x64のタイル、3バイトのBGRピクセル
//   1000  （0x3e8）白黒: 1ピクセル1ビット、MSBから、1が白
//   1001  （0x3e9）16階調グレー: 1ピクセル4ビット、上位ニブルから
//   1002  （0x3ea）数千色: ビッグエンディアンのx1R5G5B5。RFCの"5-6-5"は
//         誤り（同じ画面をH.264で見たものと比べて確かめた）
// 1ビットと4ビットのエンコーディングの行は、バイト単位に切り上げて詰めてある。
// これらはApple Remote Desktopの古い画質の段階（白黒、グレー、数千色、
// 数百万色）にあたる。
//   1011  （0x3f3）AppleのDCTコーデック。画面共有の画質「Adaptive」
//         （session/apple_dct.h）
#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "core/bytes.h"
#include "session/apple_dct.h"
#include "session/control_messages.h"
#include "util/zlib.h"

namespace iss::session {

struct FbRect {
  int x = 0, y = 0, w = 0, h = 0;
};

class Framebuffer {
 public:
  void resize(int width, int height);
  int width() const { return w_; }
  int height() const { return h_; }
  // 行優先で、1行にwidth()ピクセル。0xAARRGGBB（バイト列ではBGRA）、アルファ255。
  const uint32_t* pixels() const { return px_.data(); }

  // 1つの矩形をデコードしてキャンバスに書く。ペイロードの中身がおかしいか、デコード
  // しないエンコーディングならfalse（理由も返す）。失敗した矩形のzlibストリームは
  // そこで位置がずれるので、サーバーが新しいストリームを始めるまで、同じエンコーディングの
  // 後続の矩形も失敗する。
  bool apply(const PixelRect& r, std::string* error = nullptr);

  // 前回の呼び出し以降に変わったキャンバスの領域（多ければまとめる）。
  std::vector<FbRect> take_dirty();

 private:
  bool zlib_chunk(int32_t encoding, const uint8_t* p, size_t n, size_t expect, std::string* error);
  bool zrle(const PixelRect& r, std::string* error);
  void mark(int x, int y, int w, int h);
  uint32_t* row(int y) { return px_.data() + size_t(y) * w_; }

  int w_ = 0, h_ = 0;
  std::vector<uint32_t> px_;
  std::vector<FbRect> dirty_;
  // zlibストリームはエンコーディングごとに1本。zlibヘッダで始まる部分は新しい
  // ストリームを始める。ヘッダで始まらない部分がまだストリームのないエンコーディングで
  // 来たら、最後に使ったストリームの続きとして扱う（Appleの古いコーデックは
  // 1つのdeflaterを共有することがあるため）。
  std::map<int32_t, zlib::Inflater> streams_;
  int32_t last_stream_ = 0;
  Bytes inflated_;
  AppleDctDecoder dct_;
};

}  // namespace iss::session
