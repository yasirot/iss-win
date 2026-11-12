// H.264/HEVCのビットストリームを扱う基本部品（media/bitstream.pyの移植）。
// emulation preventionの除去と、MSBから読むexp-Golombリーダーを持つ。
// Python版のリーダーと同じく、末尾を越えて読んでも失敗せず0のビットを返す。
#pragma once

#include <cstdint>

#include "core/bytes.h"

namespace iss::media {

// `00 00 03` を `00 00` に戻す（RBSPの取り出し）。
Bytes remove_emulation_prevention(const uint8_t* p, size_t n);
inline Bytes remove_emulation_prevention(const Bytes& b) { return remove_emulation_prevention(b.data(), b.size()); }

class BitReader {
 public:
  BitReader(const uint8_t* p, size_t n) : p_(p), n_(n) {}
  explicit BitReader(const Bytes& b) : BitReader(b.data(), b.size()) {}

  size_t pos() const { return pos_; }

  uint32_t read1() {
    size_t byte = pos_ >> 3;
    if (byte >= n_) return 0;
    uint32_t bit = 7 - (pos_ & 7);
    ++pos_;
    return (p_[byte] >> bit) & 1;
  }

  uint64_t read(int bits) {
    uint64_t v = 0;
    for (int i = 0; i < bits; ++i) v = (v << 1) | read1();
    return v;
  }

  // ue(v)。不正な入力で回り続けないよう、先頭の0の数は32で打ち切る。
  uint64_t read_ue() {
    int zeros = 0;
    for (;;) {
      uint32_t b = read1();
      if (!(b == 0 && zeros < 32)) break;
      ++zeros;
    }
    uint64_t suffix = 0;
    for (int i = zeros - 1; i >= 0; --i) suffix |= uint64_t(read1()) << i;
    return ((uint64_t(1) << zeros) - 1) + suffix;
  }

  int64_t read_se() {
    uint64_t code = read_ue();
    return (code & 1) ? static_cast<int64_t>((code + 1) / 2) : -static_cast<int64_t>(code / 2);
  }

 private:
  const uint8_t* p_;
  size_t n_;
  size_t pos_ = 0;
};

}  // namespace iss::media
