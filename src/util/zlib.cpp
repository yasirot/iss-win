#include "util/zlib.h"

#include <array>

namespace iss::zlib {

uint32_t adler32(const uint8_t* p, size_t n, uint32_t adler) {
  uint32_t a = adler & 0xFFFF, b = adler >> 16;
  while (n) {
    size_t chunk = n < 5552 ? n : 5552;  // uint32があふれない最大のn
    n -= chunk;
    while (chunk--) {
      a += *p++;
      b += a;
    }
    a %= 65521;
    b %= 65521;
  }
  return (b << 16) | a;
}

Bytes compress_stored(const Bytes& data) {
  ByteWriter w(data.size() + data.size() / 65535 * 5 + 11);
  w.u8(0x78).u8(0x01);  // CMFはdeflateで32Kウィンドウ。FLGは最速で、チェックビットも正しい
  size_t pos = 0;
  do {
    size_t len = std::min<size_t>(data.size() - pos, 65535);
    bool final_block = pos + len == data.size();
    w.u8(final_block ? 1 : 0);  // BFINAL、BTYPE=00（stored）
    w.le16(static_cast<uint16_t>(len)).le16(static_cast<uint16_t>(~len));
    w.raw(data.data() + pos, len);
    pos += len;
  } while (pos < data.size());
  w.be32(adler32(data.data(), data.size()));
  return w.take();
}

namespace {

class BitIn {
 public:
  BitIn(const uint8_t* p, size_t n) : p_(p), n_(n) {}
  // 入力が尽きたらfalseを返す。
  bool bits(int count, uint32_t& out) {
    while (have_ < count) {
      if (pos_ >= n_) return false;
      buf_ |= uint32_t(p_[pos_++]) << have_;
      have_ += 8;
    }
    out = buf_ & ((1u << count) - 1);
    buf_ >>= count;
    have_ -= count;
    return true;
  }
  void align() { buf_ = 0; have_ = 0; }
  size_t pos() const { return pos_; }
  const uint8_t* data() const { return p_; }
  size_t size() const { return n_; }
  void advance(size_t k) { pos_ += k; }

 private:
  const uint8_t* p_;
  size_t n_;
  size_t pos_ = 0;
  uint32_t buf_ = 0;
  int have_ = 0;
};

// canonical Huffmanの復号テーブル（符号長ごとの個数と、符号順に並べたシンボル）。
struct Huffman {
  std::array<uint16_t, 16> count{};
  std::array<uint16_t, 320> symbol{};

  bool build(const uint8_t* lengths, int n) {
    count.fill(0);
    for (int i = 0; i < n; ++i) count[lengths[i]]++;
    count[0] = 0;
    int left = 1;
    for (int len = 1; len < 16; ++len) {
      left <<= 1;
      left -= count[len];
      if (left < 0) return false;  // 符号が多すぎる
    }
    std::array<uint16_t, 16> offs{};
    for (int len = 1; len < 15; ++len) offs[len + 1] = offs[len] + count[len];
    for (int i = 0; i < n; ++i) {
      if (lengths[i]) symbol[offs[lengths[i]]++] = static_cast<uint16_t>(i);
    }
    return true;
  }

  int decode(BitIn& in) const {
    int code = 0, first = 0, index = 0;
    for (int len = 1; len < 16; ++len) {
      uint32_t bit;
      if (!in.bits(1, bit)) return -1;
      code |= static_cast<int>(bit);
      int c = count[len];
      if (code - c < first) return symbol[index + (code - first)];
      index += c;
      first += c;
      first <<= 1;
      code <<= 1;
    }
    return -1;
  }
};

constexpr uint16_t kLenBase[] = {3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
                                 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258};
constexpr uint8_t kLenExtra[] = {0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
                                 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0};
constexpr uint16_t kDistBase[] = {1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129,
                                  193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097,
                                  6145, 8193, 12289, 16385, 24577};
constexpr uint8_t kDistExtra[] = {0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6,
                                  6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13};

bool inflate_codes(BitIn& in, Bytes& out, const Huffman& lit, const Huffman& dist, size_t max_out) {
  for (;;) {
    int sym = lit.decode(in);
    if (sym < 0) return false;
    if (sym < 256) {
      if (out.size() >= max_out) return false;
      out.push_back(static_cast<uint8_t>(sym));
    } else if (sym == 256) {
      return true;
    } else {
      sym -= 257;
      if (sym >= 29) return false;
      uint32_t extra;
      if (!in.bits(kLenExtra[sym], extra)) return false;
      size_t len = kLenBase[sym] + extra;
      int ds = dist.decode(in);
      if (ds < 0 || ds >= 30) return false;
      if (!in.bits(kDistExtra[ds], extra)) return false;
      size_t d = kDistBase[ds] + extra;
      if (d > out.size() || out.size() + len > max_out) return false;
      size_t from = out.size() - d;
      for (size_t i = 0; i < len; ++i) out.push_back(out[from + i]);  // 範囲が重なることがある
    }
  }
}

bool inflate_stored(BitIn& in, Bytes& out, size_t max_out) {
  in.align();
  size_t p = in.pos();
  if (p + 4 > in.size()) return false;
  const uint8_t* d = in.data();
  uint16_t len = uint16_t(d[p] | (d[p + 1] << 8));
  uint16_t nlen = uint16_t(d[p + 2] | (d[p + 3] << 8));
  if (len != static_cast<uint16_t>(~nlen)) return false;
  p += 4;
  if (p + len > in.size() || out.size() + len > max_out) return false;
  out.insert(out.end(), d + p, d + p + len);
  in.advance(4 + len);
  return true;
}

bool inflate_fixed(BitIn& in, Bytes& out, size_t max_out) {
  static const auto tables = [] {
    std::pair<Huffman, Huffman> t;
    uint8_t lens[288];
    for (int i = 0; i < 144; ++i) lens[i] = 8;
    for (int i = 144; i < 256; ++i) lens[i] = 9;
    for (int i = 256; i < 280; ++i) lens[i] = 7;
    for (int i = 280; i < 288; ++i) lens[i] = 8;
    t.first.build(lens, 288);
    uint8_t dl[30];
    for (auto& l : dl) l = 5;
    t.second.build(dl, 30);
    return t;
  }();
  return inflate_codes(in, out, tables.first, tables.second, max_out);
}

bool inflate_dynamic(BitIn& in, Bytes& out, size_t max_out) {
  uint32_t hlit, hdist, hclen;
  if (!in.bits(5, hlit) || !in.bits(5, hdist) || !in.bits(4, hclen)) return false;
  hlit += 257;
  hdist += 1;
  hclen += 4;
  if (hlit > 286 || hdist > 30) return false;

  static const uint8_t kOrder[19] = {16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15};
  uint8_t cl_lens[19] = {};
  for (uint32_t i = 0; i < hclen; ++i) {
    uint32_t v;
    if (!in.bits(3, v)) return false;
    cl_lens[kOrder[i]] = static_cast<uint8_t>(v);
  }
  Huffman cl;
  if (!cl.build(cl_lens, 19)) return false;

  uint8_t lens[320] = {};
  uint32_t idx = 0;
  while (idx < hlit + hdist) {
    int sym = cl.decode(in);
    if (sym < 0) return false;
    if (sym < 16) {
      lens[idx++] = static_cast<uint8_t>(sym);
      continue;
    }
    uint8_t value = 0;
    uint32_t rep;
    if (sym == 16) {
      if (idx == 0 || !in.bits(2, rep)) return false;
      value = lens[idx - 1];
      rep += 3;
    } else if (sym == 17) {
      if (!in.bits(3, rep)) return false;
      rep += 3;
    } else {
      if (!in.bits(7, rep)) return false;
      rep += 11;
    }
    if (idx + rep > hlit + hdist) return false;
    while (rep--) lens[idx++] = value;
  }
  if (lens[256] == 0) return false;  // end-of-blockの符号がない

  Huffman lit, dist;
  if (!lit.build(lens, static_cast<int>(hlit)) || !dist.build(lens + hlit, static_cast<int>(hdist))) return false;
  return inflate_codes(in, out, lit, dist, max_out);
}

}  // namespace

std::optional<Bytes> decompress(const uint8_t* p, size_t n, size_t max_out) {
  if (n < 6) return std::nullopt;
  uint8_t cmf = p[0], flg = p[1];
  if ((cmf & 0x0F) != 8 || (cmf >> 4) > 7) return std::nullopt;  // deflateで、ウィンドウは32K以下
  if (((cmf << 8) | flg) % 31) return std::nullopt;
  if (flg & 0x20) return std::nullopt;  // preset dictionaryは扱わない

  BitIn in(p + 2, n - 6);
  Bytes out;
  for (;;) {
    uint32_t final_block, type;
    if (!in.bits(1, final_block) || !in.bits(2, type)) return std::nullopt;
    bool ok = type == 0 ? inflate_stored(in, out, max_out)
            : type == 1 ? inflate_fixed(in, out, max_out)
            : type == 2 ? inflate_dynamic(in, out, max_out)
                        : false;
    if (!ok) return std::nullopt;
    if (final_block) break;
  }
  if (rd_be32(p + n - 4) != adler32(out.data(), out.size())) return std::nullopt;
  return out;
}

// ── チャンク単位でテーブル引きのinflater ────────────────────────────────

namespace {

// 64ビットのバッファを持つ、LSBから読むビットリーダー。
class FastBits {
 public:
  FastBits(const uint8_t* p, size_t n) : p_(p), end_(p + n) {}
  void refill() {
    while (count_ <= 56 && p_ < end_) {
      buf_ |= uint64_t(*p_++) << count_;
      count_ += 8;
    }
  }
  // 次のnビット。入力の末尾を越えた位置は0として読む。
  uint32_t peek(int n) const { return static_cast<uint32_t>(buf_ & ((uint64_t(1) << n) - 1)); }
  void consume(int n) {
    buf_ >>= n;
    count_ -= n;
  }
  int count() const { return count_; }
  bool bits(int n, uint32_t& out) {
    refill();
    if (n > count_) return false;
    out = peek(n);
    consume(n);
    return true;
  }
  void align() { consume(count_ % 8); }
  bool at_end() const { return count_ == 0 && p_ >= end_; }
  // align()のあとに呼ぶ。生の `len` バイトを、まずビットバッファから、次に入力から取る。
  bool copy_bytes(Bytes& dst, size_t len) {
    while (len && count_ >= 8) {
      dst.push_back(static_cast<uint8_t>(buf_));
      consume(8);
      --len;
    }
    if (static_cast<size_t>(end_ - p_) < len) return false;
    dst.insert(dst.end(), p_, p_ + len);
    p_ += len;
    return true;
  }
  // まだ読んでいないバイト数（align()のあとで使う）。
  size_t bytes_left() const { return count_ / 8 + static_cast<size_t>(end_ - p_); }

 private:
  const uint8_t* p_;
  const uint8_t* end_;
  uint64_t buf_ = 0;
  int count_ = 0;
};

// canonical Huffman符号を、ストリームの次のmax_lenビットで引く1枚のテーブルにした
// もの。要素はsymbol << 4 | 符号長（0は符号なし）。
struct FastHuffman {
  std::vector<uint16_t> table;
  int max_len = 0;

  bool build(const uint8_t* lengths, int n) {
    int count[16] = {};
    for (int i = 0; i < n; ++i) count[lengths[i]]++;
    count[0] = 0;
    max_len = 0;
    for (int len = 1; len < 16; ++len) {
      if (count[len]) max_len = len;
    }
    int left = 1;
    for (int len = 1; len < 16; ++len) {
      left = (left << 1) - count[len];
      if (left < 0) return false;  // 符号が多すぎる
    }
    table.assign(max_len ? size_t(1) << max_len : 0, 0);
    int next[16] = {};
    for (int len = 1, code = 0; len < 16; ++len) {
      code = (code + count[len - 1]) << 1;
      next[len] = code;
    }
    for (int sym = 0; sym < n; ++sym) {
      const int len = lengths[sym];
      if (!len) continue;
      const int code = next[len]++;
      int rev = 0;
      for (int b = 0; b < len; ++b) rev |= ((code >> b) & 1) << (len - 1 - b);
      for (size_t i = static_cast<size_t>(rev); i < table.size(); i += size_t(1) << len) {
        table[i] = static_cast<uint16_t>(sym << 4 | len);
      }
    }
    return true;
  }

  int decode(FastBits& in) const {
    if (!max_len) return -1;
    in.refill();
    const uint16_t e = table[in.peek(max_len)];
    const int len = e & 15;
    if (!len || len > in.count()) return -1;
    in.consume(len);
    return e >> 4;
  }
};

bool fast_codes(FastBits& in, Bytes& buf, const FastHuffman& lit, const FastHuffman& dist, size_t limit) {
  for (;;) {
    const int sym = lit.decode(in);
    if (sym < 0) return false;
    if (sym < 256) {
      if (buf.size() >= limit) return false;
      buf.push_back(static_cast<uint8_t>(sym));
      continue;
    }
    if (sym == 256) return true;
    const int li = sym - 257;
    if (li >= 29) return false;
    uint32_t extra = 0;
    if (kLenExtra[li] && !in.bits(kLenExtra[li], extra)) return false;
    const size_t len = kLenBase[li] + extra;
    const int di = dist.decode(in);
    if (di < 0 || di >= 30) return false;
    extra = 0;
    if (kDistExtra[di] && !in.bits(kDistExtra[di], extra)) return false;
    const size_t d = kDistBase[di] + extra;
    if (d > buf.size() || buf.size() + len > limit) return false;
    const size_t from = buf.size() - d;
    buf.resize(buf.size() + len);
    uint8_t* o = buf.data() + buf.size() - len;
    const uint8_t* s = buf.data() + from;
    for (size_t i = 0; i < len; ++i) o[i] = s[i];  // 範囲が重なることがある
  }
}

const std::pair<FastHuffman, FastHuffman>& fixed_tables() {
  static const auto tables = [] {
    std::pair<FastHuffman, FastHuffman> t;
    uint8_t lens[288];
    for (int i = 0; i < 144; ++i) lens[i] = 8;
    for (int i = 144; i < 256; ++i) lens[i] = 9;
    for (int i = 256; i < 280; ++i) lens[i] = 7;
    for (int i = 280; i < 288; ++i) lens[i] = 8;
    t.first.build(lens, 288);
    uint8_t dl[30];
    for (auto& l : dl) l = 5;
    t.second.build(dl, 30);
    return t;
  }();
  return tables;
}

bool fast_dynamic(FastBits& in, Bytes& buf, size_t limit) {
  uint32_t hlit, hdist, hclen;
  if (!in.bits(5, hlit) || !in.bits(5, hdist) || !in.bits(4, hclen)) return false;
  hlit += 257;
  hdist += 1;
  hclen += 4;
  if (hlit > 286 || hdist > 30) return false;
  static const uint8_t kOrder[19] = {16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15};
  uint8_t cl_lens[19] = {};
  for (uint32_t i = 0; i < hclen; ++i) {
    uint32_t v;
    if (!in.bits(3, v)) return false;
    cl_lens[kOrder[i]] = static_cast<uint8_t>(v);
  }
  FastHuffman cl;
  if (!cl.build(cl_lens, 19)) return false;
  uint8_t lens[320] = {};
  uint32_t idx = 0;
  while (idx < hlit + hdist) {
    const int sym = cl.decode(in);
    if (sym < 0) return false;
    if (sym < 16) {
      lens[idx++] = static_cast<uint8_t>(sym);
      continue;
    }
    uint8_t value = 0;
    uint32_t rep;
    if (sym == 16) {
      if (idx == 0 || !in.bits(2, rep)) return false;
      value = lens[idx - 1];
      rep += 3;
    } else if (sym == 17) {
      if (!in.bits(3, rep)) return false;
      rep += 3;
    } else {
      if (!in.bits(7, rep)) return false;
      rep += 11;
    }
    if (idx + rep > hlit + hdist) return false;
    while (rep--) lens[idx++] = value;
  }
  if (lens[256] == 0) return false;
  FastHuffman lit, dist;
  if (!lit.build(lens, static_cast<int>(hlit)) || !dist.build(lens + hlit, static_cast<int>(hdist))) return false;
  return fast_codes(in, buf, lit, dist, limit);
}

constexpr size_t kWindow = 32768;

}  // namespace

bool looks_like_zlib_header(const uint8_t* p, size_t n) {
  if (n < 2) return false;
  const uint8_t cmf = p[0], flg = p[1];
  return (cmf & 0x0F) == 8 && (cmf >> 4) <= 7 && ((cmf << 8) | flg) % 31 == 0 && !(flg & 0x20);
}

void Inflater::reset() {
  window_.clear();
  started_ = false;
  failed_ = false;
}

bool Inflater::inflate(const uint8_t* p, size_t n, Bytes& out, size_t max_out) {
  if (failed_) return false;
  size_t start = 0;
  if (!started_) {
    if (!looks_like_zlib_header(p, n)) {
      failed_ = true;
      return false;
    }
    start = 2;
    started_ = true;
  }
  // 後方参照がウィンドウまで届くよう、ウィンドウの後ろに続けてデコードする。
  Bytes buf;
  buf.reserve(window_.size() + n * 4 + 4096);
  buf = window_;
  const size_t base = buf.size(), limit = base + max_out;
  FastBits in(p + start, n - start);
  for (;;) {
    in.refill();
    if (in.at_end()) break;  // チャンクがブロック境界で終わった
    uint32_t final_block, type;
    if (!in.bits(1, final_block) || !in.bits(2, type)) {
      failed_ = true;
      return false;
    }
    bool ok = false;
    if (type == 0) {
      in.align();
      uint32_t len, nlen;
      ok = in.bits(16, len) && in.bits(16, nlen) && len == (~nlen & 0xFFFF) && buf.size() + len <= limit &&
           in.copy_bytes(buf, len);
    } else if (type == 1) {
      ok = fast_codes(in, buf, fixed_tables().first, fixed_tables().second, limit);
    } else if (type == 2) {
      ok = fast_dynamic(in, buf, limit);
    }
    if (!ok) {
      failed_ = true;
      return false;
    }
    if (final_block) {  // ストリームが終わる。ヘッダー付きの新しいストリームが続くことがある
      in.align();
      started_ = false;
      break;
    }
  }
  out.insert(out.end(), buf.begin() + static_cast<std::ptrdiff_t>(base), buf.end());
  const size_t keep = std::min(buf.size(), kWindow);
  window_.assign(buf.end() - static_cast<std::ptrdiff_t>(keep), buf.end());
  if (!started_) window_.clear();
  return true;
}

std::optional<Bytes> decompress_sync_flushed(const uint8_t* p, size_t n, size_t max_out) {
  if (n < 2) return std::nullopt;
  uint8_t cmf = p[0], flg = p[1];
  if ((cmf & 0x0F) != 8 || (cmf >> 4) > 7) return std::nullopt;
  if (((cmf << 8) | flg) % 31) return std::nullopt;
  if (flg & 0x20) return std::nullopt;

  // sync flushはバイト境界（空のstoredブロック）で終わるので、ストリームは
  // 入力が尽きたところでちょうど終わる。
  BitIn in(p + 2, n - 2);
  Bytes out;
  while (in.pos() < in.size()) {
    uint32_t final_block, type;
    if (!in.bits(1, final_block) || !in.bits(2, type)) return std::nullopt;
    bool ok = type == 0 ? inflate_stored(in, out, max_out)
            : type == 1 ? inflate_fixed(in, out, max_out)
            : type == 2 ? inflate_dynamic(in, out, max_out)
                        : false;
    if (!ok) return std::nullopt;
    if (final_block) break;  // ふつうのストリーム。トレーラーが続くが確かめない
  }
  return out;
}

}  // namespace iss::zlib
