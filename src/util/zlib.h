// DEFLATE（RFC 1951）を包む最小限のzlib（RFC 1950）コンテナ。
//
// offerのデータは数百バイトしかないので、圧縮ではstored（無圧縮）ブロックを出す。
// これも正しいzlibなので、どのinflaterでも受け付ける。サーバーの応答はAppleの
// libzで圧縮されているため、展開側は完全なinflater（stored、固定Huffman、
// 動的Huffmanのブロック）として実装している。
#pragma once

#include <optional>

#include "core/bytes.h"

namespace iss::zlib {

uint32_t adler32(const uint8_t* p, size_t n, uint32_t adler = 1);

Bytes compress_stored(const Bytes& data);

// 入力が不正、チェックサムが合わない、出力が `max_out` を超える、のどれかならnullopt。
std::optional<Bytes> decompress(const uint8_t* p, size_t n, size_t max_out = 64 << 20);
inline std::optional<Bytes> decompress(const Bytes& b, size_t max_out = 64 << 20) {
  return decompress(b.data(), b.size(), max_out);
}

// 最終ブロックとAdler-32のトレーラーで終わらず、sync flush（空のstoredブロック）
// のところで止まることがあるzlibストリームを展開する。Appleのカーソルの
// pixmapがそういう終わり方をする（Python版はdecompressobjで読む）。入力の末尾まで
// すべてのブロックを展開し、チェックサムは確かめない。
std::optional<Bytes> decompress_sync_flushed(const uint8_t* p, size_t n, size_t max_out = 64 << 20);

// 1本のzlibストリームを、それぞれdeflateのブロック境界で終わるチャンクに分けて
// デコードする。RFBのzlib系エンコーディング用で、ストリームは接続のあいだずっと
// 続き、矩形1つがZ_SYNC_FLUSHで閉じた1チャンクになる。後方参照は32 KiBの
// ウィンドウを通して前のチャンクまで届く。数メガバイトある全画面の更新に
// 備えて、テーブル引きで実装している。
class Inflater {
 public:
  // チャンクの出力を `out` に追加する。最初のチャンク（と、最終ブロックのあとの
  // 最初のチャンク）は2バイトのzlibヘッダーで始まる。データが壊れているか、出力が
  // `max_out` を超えるとfalseを返し、そのあとはreset()するまでストリームを使えない。
  bool inflate(const uint8_t* p, size_t n, Bytes& out, size_t max_out = 64 << 20);
  void reset();
  bool started() const { return started_; }

 private:
  Bytes window_;  // 出力の末尾、最大32 KiB
  bool started_ = false;
  bool failed_ = false;
};

// `p` がzlibヘッダーで始まるか（CMF/FLGを確かめ、preset dictionaryなしに限る）。
bool looks_like_zlib_header(const uint8_t* p, size_t n);

}  // namespace iss::zlib
