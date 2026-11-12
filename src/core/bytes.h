// バイト列と、ビッグエンディアンで詰める補助関数（RFBの通信はほぼすべて
// ビッグエンディアン。少しだけあるリトルエンディアンのフィールドは、使う場所で
// そう明記する）。
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace iss {

using Bytes = std::vector<uint8_t>;

inline uint16_t rd_be16(const uint8_t* p) { return uint16_t((p[0] << 8) | p[1]); }
inline uint32_t rd_be32(const uint8_t* p) {
  return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | p[3];
}
inline uint64_t rd_be64(const uint8_t* p) {
  return (uint64_t(rd_be32(p)) << 32) | rd_be32(p + 4);
}
inline void wr_be16(uint8_t* p, uint16_t v) { p[0] = uint8_t(v >> 8); p[1] = uint8_t(v); }
inline void wr_be32(uint8_t* p, uint32_t v) {
  p[0] = uint8_t(v >> 24); p[1] = uint8_t(v >> 16); p[2] = uint8_t(v >> 8); p[3] = uint8_t(v);
}
inline void wr_be64(uint8_t* p, uint64_t v) { wr_be32(p, uint32_t(v >> 32)); wr_be32(p + 4, uint32_t(v)); }

// 後ろに足していくだけのビルダー。Python実装の `struct.pack(">...")` の連なりに
// 合わせた形にして、移植したコードを1行ずつ見比べられるようにしている。
class ByteWriter {
 public:
  ByteWriter() = default;
  explicit ByteWriter(size_t reserve) { buf_.reserve(reserve); }

  ByteWriter& u8(uint8_t v) { buf_.push_back(v); return *this; }
  ByteWriter& be16(uint16_t v) { uint8_t b[2]; wr_be16(b, v); return raw(b, 2); }
  ByteWriter& be32(uint32_t v) { uint8_t b[4]; wr_be32(b, v); return raw(b, 4); }
  ByteWriter& be64(uint64_t v) { uint8_t b[8]; wr_be64(b, v); return raw(b, 8); }
  ByteWriter& le16(uint16_t v) { u8(uint8_t(v)); return u8(uint8_t(v >> 8)); }
  ByteWriter& f32be(float v) { uint32_t u; std::memcpy(&u, &v, 4); return be32(u); }
  ByteWriter& f64be(double v) { uint64_t u; std::memcpy(&u, &v, 8); return be64(u); }
  ByteWriter& raw(const void* p, size_t n) {
    auto* b = static_cast<const uint8_t*>(p);
    buf_.insert(buf_.end(), b, b + n);
    return *this;
  }
  ByteWriter& bytes(const Bytes& b) { return raw(b.data(), b.size()); }
  ByteWriter& str(std::string_view s) { return raw(s.data(), s.size()); }
  ByteWriter& zeros(size_t n) { buf_.insert(buf_.end(), n, 0); return *this; }

  size_t size() const { return buf_.size(); }
  const Bytes& data() const { return buf_; }
  Bytes take() { return std::move(buf_); }

 private:
  Bytes buf_;
};

// サーバーのメッセージをパースする、範囲チェック付きで先頭から順に読むリーダー。
// Pythonのスライスのように知らないうちに切り詰めず、std::out_of_rangeを投げる。
class ByteReader {
 public:
  ByteReader(const uint8_t* p, size_t n) : p_(p), n_(n) {}
  explicit ByteReader(const Bytes& b) : ByteReader(b.data(), b.size()) {}

  size_t pos() const { return pos_; }
  size_t remaining() const { return n_ - pos_; }
  void skip(size_t k) { need(k); pos_ += k; }
  uint8_t u8() { need(1); return p_[pos_++]; }
  uint16_t be16() { need(2); auto v = rd_be16(p_ + pos_); pos_ += 2; return v; }
  uint32_t be32() { need(4); auto v = rd_be32(p_ + pos_); pos_ += 4; return v; }
  uint64_t be64() { need(8); auto v = rd_be64(p_ + pos_); pos_ += 8; return v; }
  Bytes take(size_t k) { need(k); Bytes out(p_ + pos_, p_ + pos_ + k); pos_ += k; return out; }

 private:
  void need(size_t k) const {
    if (k > n_ - pos_) throw std::out_of_range("ByteReader: truncated input");
  }
  const uint8_t* p_;
  size_t n_;
  size_t pos_ = 0;
};

std::string to_hex(const uint8_t* p, size_t n);
inline std::string to_hex(const Bytes& b) { return to_hex(b.data(), b.size()); }
Bytes from_hex(std::string_view hex);

inline Bytes slice(const Bytes& b, size_t off, size_t len) {
  if (off > b.size() || len > b.size() - off) throw std::out_of_range("slice");
  return Bytes(b.begin() + off, b.begin() + off + len);
}

// 秘密（パスワード、鍵）を入れていたメモリを上書きしてから解放する。
void secure_wipe(void* p, size_t n);
inline void secure_wipe(Bytes& b) { secure_wipe(b.data(), b.size()); b.clear(); }
inline void secure_wipe(std::string& s) { secure_wipe(s.data(), s.size()); s.clear(); }

}  // namespace iss
