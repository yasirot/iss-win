// 標準モード（画質「Adaptive」）で使うAppleのDCTコーデック。RFBのエンコーディング
// 1011（0x3f3）で、screensharingdでは"Multi-Variant Scaled"と呼ばれる。ビット
// ストリームの形式はrootshell-vncのAppleAdaptiveDCTDecoder（MIT、(c) 2026
// Rootshell LLC, Kit Knox。THIRD_PARTY_NOTICES.mdを参照）に従う。整数IDCTと
// YCbCrの変換はstb_imageのもの（public domain / MIT）。
//
// ペイロードはu32の長さのあとにメッセージが続き、メッセージの先頭バイトが種類を表す。
//   2  量子化テーブル。輝度64バイト + 色差64バイト（自然順）
//   0  画像コマンド。u8の低カットオフ、u8の高カットオフ、u24のデータオフセットの
//      あとに、データオフセットまでがコマンドのビットストリーム、それ以降がデータの
//      ビットストリーム（どちらもMSBから）。矩形は8x8のタイルに行優先で分け、
//      各コマンドは3ビット + ランレングス。
//        0 白、1 直前のタイルのコピー、2 上のタイルのコピー、
//        3 白黒の2色、4 YCbCrで色を指定した単色 / 2色、
//        5 DCT（輝度AC + 色差DC）、6 / 7 キャッシュにある改良済みのタイル
//   1  前に送ったタイルの段階的な改良（しきい値2つのあと、タイルごとに2ビット）。
//      輝度ACを増やし、色差ACを足し、リングのインデックスでキャッシュに入れる
// デコーダは接続している間ずっと全タイルの係数を持ち続ける。改良とキャッシュが、
// 前の矩形でデコードしたタイルを参照するため。
#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace iss::session {

class AppleDctDecoder {
 public:
  AppleDctDecoder();
  ~AppleDctDecoder();

  // `payload`は矩形のペイロード（u32の長さ + メッセージ）。`fb`は画面で、行優先、
  // 0xAARRGGBB。データの形がおかしければfalse（理由も返す）。
  bool apply(int x, int y, int w, int h, const uint8_t* payload, size_t n, uint32_t* fb, int fb_w, int fb_h,
             std::string* error);

  // 1つのタイルの係数。Y、Cb、Cr（それぞれ64個、自然順）と、改良の対象になる
  // 符号化された値（Y 0-63、Cb 64-83、Cr 84-98）。
  struct Tile {
    std::array<int16_t, 192> values{};
    std::array<int8_t, 99> map{};
    int quality = -1;  // -1は一度もデコードしていないこと
    uint8_t cb_count = 0, cr_count = 0;
  };

 private:
  struct TileMeta {
    int validation_source = -1, pixel_source = -1;  // コピー元の参照（種類1、コマンド2）
    uint64_t generation = 0;
  };
  class Bits;

  void ensure_size(int fb_w, int fb_h);
  void image(int x, int y, int w, int h, const uint8_t* msg, size_t n, uint32_t* fb, int fb_w, int fb_h);
  void refinement(int x, int y, int w, int h, const uint8_t* msg, size_t n, uint32_t* fb, int fb_w, int fb_h);
  void decode_new_tile(Bits& data, int low_cutoff, int high_cutoff);
  Tile refine(const Tile& old, Bits& bits, int threshold1, int threshold2);
  const Tile& cached(int index);
  void to_pixels(const Tile& t, uint32_t out[64]) const;

  std::array<uint16_t, 64> luma_q_{}, chroma_q_{};
  int fb_w_ = 0, fb_h_ = 0;
  std::vector<Tile> tiles_;
  std::vector<TileMeta> meta_;
  uint64_t generation_ = 0;
  // 改良済みのタイル。リングのインデックス1..64999で引く。ページは初めて使うときに確保する。
  std::vector<std::unique_ptr<std::array<Tile, 256>>> cache_;
  int cache_write_ = 0, cache_read_ = 0;
  // 1つの画像メッセージの中で、タイルからタイルへ引き継ぐ状態。
  Tile predictor_;
  uint32_t solid_ = 0, first_ = 0, second_ = 0;
  bool have_solid_ = false, have_palette_ = false;
  Tile zero_;
};

}  // namespace iss::session
