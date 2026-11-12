// AVCMediaStreamNegotiatorのblobを扱うのに足りるだけのprotobufワイヤーフォーマット。
#pragma once

#include <cstdint>
#include <functional>
#include <string_view>

#include "core/bytes.h"

namespace iss::pb {

inline void put_varint(ByteWriter& w, uint64_t v) {
  while (v > 0x7F) {
    w.u8(static_cast<uint8_t>((v & 0x7F) | 0x80));
    v >>= 7;
  }
  w.u8(static_cast<uint8_t>(v));
}

inline void field_varint(ByteWriter& w, uint32_t field, uint64_t value) {
  put_varint(w, (uint64_t(field) << 3) | 0);
  put_varint(w, value);
}

inline void field_bytes(ByteWriter& w, uint32_t field, const uint8_t* p, size_t n) {
  put_varint(w, (uint64_t(field) << 3) | 2);
  put_varint(w, n);
  w.raw(p, n);
}
inline void field_bytes(ByteWriter& w, uint32_t field, const Bytes& b) { field_bytes(w, field, b.data(), b.size()); }
inline void field_bytes(ByteWriter& w, uint32_t field, std::string_view s) {
  field_bytes(w, field, reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

// varintを読む。Python版のヘルパーと同じく、入力の終わりで止まる（エラーにしない）。
inline uint64_t read_varint(const uint8_t* p, size_t n, size_t& pos) {
  uint64_t v = 0;
  int shift = 0;
  while (pos < n) {
    uint8_t b = p[pos++];
    if (shift < 64) v |= uint64_t(b & 0x7F) << shift;
    shift += 7;
    if (!(b & 0x80)) break;
  }
  return v;
}

struct Field {
  uint32_t number;
  uint32_t wire_type;
  uint64_t varint = 0;          // wire type 0
  const uint8_t* data = nullptr;  // wire type 2
  size_t size = 0;
};

// メッセージのトップレベルをたどり、フィールドごとに`fn`を呼ぶ。未知のwire typeか、
// 末尾を越える長さに当たるとfalseを返す（Python版のパーサーと同じく、走査は
// そこで止まる）。
inline bool for_each_field(const uint8_t* p, size_t n, const std::function<void(const Field&)>& fn) {
  size_t pos = 0;
  while (pos < n) {
    uint64_t tag = read_varint(p, n, pos);
    Field f{static_cast<uint32_t>(tag >> 3), static_cast<uint32_t>(tag & 7)};
    switch (f.wire_type) {
      case 0: f.varint = read_varint(p, n, pos); break;
      case 1: if (pos + 8 > n) return false; pos += 8; break;
      case 5: if (pos + 4 > n) return false; pos += 4; break;
      case 2: {
        uint64_t len = read_varint(p, n, pos);
        if (len > n - pos) return false;
        f.data = p + pos;
        f.size = static_cast<size_t>(len);
        pos += f.size;
        break;
      }
      default: return false;
    }
    fn(f);
  }
  return true;
}

}  // namespace iss::pb
