#include "session/framebuffer.h"

#include <algorithm>
#include <climits>
#include <cstring>
#include <format>
#include <utility>

namespace iss::session {
namespace {

constexpr uint32_t kOpaque = 0xFF000000;
constexpr size_t kMaxDirty = 64;
constexpr int kZrleTile = 64;

uint32_t bgr(uint8_t b, uint8_t g, uint8_t r) { return kOpaque | uint32_t(r) << 16 | uint32_t(g) << 8 | b; }

bool fail(std::string* error, std::string why) {
  if (error) *error = std::move(why);
  return false;
}

}  // namespace

void Framebuffer::resize(int width, int height) {
  w_ = std::max(0, width);
  h_ = std::max(0, height);
  px_.assign(size_t(w_) * h_, kOpaque);
  dirty_.clear();
  mark(0, 0, w_, h_);
}

void Framebuffer::mark(int x, int y, int w, int h) {
  if (w <= 0 || h <= 0) return;
  dirty_.push_back({x, y, w, h});
  if (dirty_.size() <= kMaxDirty) return;
  int x0 = INT_MAX, y0 = INT_MAX, x1 = 0, y1 = 0;
  for (const FbRect& d : dirty_) {
    x0 = std::min(x0, d.x);
    y0 = std::min(y0, d.y);
    x1 = std::max(x1, d.x + d.w);
    y1 = std::max(y1, d.y + d.h);
  }
  dirty_ = {{x0, y0, x1 - x0, y1 - y0}};
}

std::vector<FbRect> Framebuffer::take_dirty() { return std::exchange(dirty_, {}); }

bool Framebuffer::zlib_chunk(int32_t encoding, const uint8_t* p, size_t n, size_t expect, std::string* error) {
  inflated_.clear();
  zlib::Inflater* z = nullptr;
  int32_t used = encoding;
  if (zlib::looks_like_zlib_header(p, n)) {
    z = &streams_[encoding];
    z->reset();
  } else if (streams_[encoding].started()) {
    z = &streams_[encoding];
  } else if (last_stream_ && streams_[last_stream_].started()) {
    z = &streams_[last_stream_];
    used = last_stream_;
  } else {
    return fail(error, std::format("encoding {}: zlib data without the start of its stream", encoding));
  }
  // `expect`が0なら事前にサイズが分からない（ZRLE）。上限は32ビットの生タイルの大きさ。
  if (!z->inflate(p, n, inflated_, expect ? expect : size_t(64) << 20)) {
    return fail(error, std::format("encoding {}: corrupt zlib data", encoding));
  }
  last_stream_ = used;
  if (expect && inflated_.size() != expect) {
    return fail(error, std::format("encoding {}: {} bytes inflated, {} expected", encoding, inflated_.size(), expect));
  }
  return true;
}

bool Framebuffer::apply(const PixelRect& r, std::string* error) {
  if (r.encoding == 1011) {  // 0x0の矩形で送られるテーブルもここで扱う
    if (!dct_.apply(r.x, r.y, r.w, r.h, r.data, r.size, px_.data(), w_, h_, error)) return false;
    mark(r.x, r.y, r.w, r.h);
    return true;
  }
  if (r.w <= 0 || r.h <= 0) return true;
  if (r.x < 0 || r.y < 0 || r.x + r.w > w_ || r.y + r.h > h_) {
    return fail(error, std::format("{}x{} at {},{} lies outside the {}x{} screen", r.w, r.h, r.x, r.y, w_, h_));
  }
  const size_t px = size_t(r.w) * r.h;
  const uint8_t* body = r.data + 4;  // zlibを使うエンコーディングのu32の長さの後ろ
  const size_t body_n = r.size >= 4 ? r.size - 4 : 0;
  switch (r.encoding) {
    case 0: {  // Raw
      if (r.size < px * 4) return fail(error, "short Raw rectangle");
      for (int y = 0; y < r.h; ++y) {
        uint32_t* d = row(r.y + y) + r.x;
        std::memcpy(d, r.data + size_t(y) * r.w * 4, size_t(r.w) * 4);
        for (int x = 0; x < r.w; ++x) d[x] |= kOpaque;
      }
      break;
    }
    case 1: {  // CopyRect
      if (r.size < 4) return fail(error, "short CopyRect");
      const int sx = rd_be16(r.data), sy = rd_be16(r.data + 2);
      if (sx + r.w > w_ || sy + r.h > h_) return fail(error, "CopyRect source outside the screen");
      // まだコピーしていないコピー元の行を上書きしない順に、行を処理する。
      for (int i = 0; i < r.h; ++i) {
        const int y = sy < r.y ? r.h - 1 - i : i;
        std::memmove(row(r.y + y) + r.x, row(sy + y) + sx, size_t(r.w) * 4);
      }
      break;
    }
    case 6: {  // zlib、32ビット
      if (!zlib_chunk(6, body, body_n, px * 4, error)) return false;
      for (int y = 0; y < r.h; ++y) {
        uint32_t* d = row(r.y + y) + r.x;
        std::memcpy(d, inflated_.data() + size_t(y) * r.w * 4, size_t(r.w) * 4);
        for (int x = 0; x < r.w; ++x) d[x] |= kOpaque;
      }
      break;
    }
    case 16:
      if (!zrle(r, error)) return false;
      break;
    case 1000: {  // 白黒
      const size_t stride = (size_t(r.w) + 7) / 8;
      if (!zlib_chunk(1000, body, body_n, stride * r.h, error)) return false;
      for (int y = 0; y < r.h; ++y) {
        const uint8_t* s = inflated_.data() + y * stride;
        uint32_t* d = row(r.y + y) + r.x;
        for (int x = 0; x < r.w; ++x) d[x] = (s[x >> 3] >> (7 - (x & 7))) & 1 ? 0xFFFFFFFF : kOpaque;
      }
      break;
    }
    case 1001: {  // 16階調グレー
      const size_t stride = (size_t(r.w) + 1) / 2;
      if (!zlib_chunk(1001, body, body_n, stride * r.h, error)) return false;
      for (int y = 0; y < r.h; ++y) {
        const uint8_t* s = inflated_.data() + y * stride;
        uint32_t* d = row(r.y + y) + r.x;
        for (int x = 0; x < r.w; ++x) {
          const uint8_t g = static_cast<uint8_t>(((s[x >> 1] >> (x & 1 ? 0 : 4)) & 15) * 17);
          d[x] = bgr(g, g, g);
        }
      }
      break;
    }
    case 1002: {  // 数千色。ビッグエンディアンのx555
      if (!zlib_chunk(1002, body, body_n, px * 2, error)) return false;
      for (int y = 0; y < r.h; ++y) {
        const uint8_t* s = inflated_.data() + size_t(y) * r.w * 2;
        uint32_t* d = row(r.y + y) + r.x;
        for (int x = 0; x < r.w; ++x) {
          const unsigned v = unsigned(s[2 * x]) << 8 | s[2 * x + 1];
          const unsigned r5 = (v >> 10) & 31, g5 = (v >> 5) & 31, b5 = v & 31;
          d[x] = bgr(static_cast<uint8_t>(b5 << 3 | b5 >> 2), static_cast<uint8_t>(g5 << 3 | g5 >> 2),
                     static_cast<uint8_t>(r5 << 3 | r5 >> 2));
        }
      }
      break;
    }
    default:
      return fail(error, std::format("encoding {} is not a pixel encoding", r.encoding));
  }
  mark(r.x, r.y, r.w, r.h);
  return true;
}

// RFC 6143 §7.7.6。64x64のタイルで、各タイルはサブエンコーディングの1バイトとその
// データ。32ビットで深さ24の形式では、ピクセルは3バイト（B、G、R）になる。
bool Framebuffer::zrle(const PixelRect& r, std::string* error) {
  if (!zlib_chunk(16, r.data + 4, r.size >= 4 ? r.size - 4 : 0, 0, error)) return false;
  const uint8_t* s = inflated_.data();
  const size_t n = inflated_.size();
  size_t pos = 0;
  auto byte = [&](uint8_t& v) {
    if (pos >= n) return false;
    v = s[pos++];
    return true;
  };
  auto cpixel = [&](uint32_t& v) {
    if (pos + 3 > n) return false;
    v = bgr(s[pos], s[pos + 1], s[pos + 2]);
    pos += 3;
    return true;
  };
  auto run_length = [&](size_t& len) {
    len = 1;
    uint8_t b;
    do {
      if (!byte(b)) return false;
      len += b;
    } while (b == 255);
    return true;
  };
  for (int ty = 0; ty < r.h; ty += kZrleTile) {
    for (int tx = 0; tx < r.w; tx += kZrleTile) {
      const int tw = std::min(kZrleTile, r.w - tx), th = std::min(kZrleTile, r.h - ty);
      const size_t total = size_t(tw) * th;
      auto put = [&](size_t i, uint32_t c) { row(r.y + ty + int(i / tw))[r.x + tx + int(i % tw)] = c; };
      uint8_t sub;
      if (!byte(sub)) return fail(error, "ZRLE: truncated");
      uint32_t palette[128];
      if (sub == 0) {
        for (size_t i = 0; i < total; ++i) {
          uint32_t c;
          if (!cpixel(c)) return fail(error, "ZRLE: truncated raw tile");
          put(i, c);
        }
      } else if (sub == 1) {
        uint32_t c;
        if (!cpixel(c)) return fail(error, "ZRLE: truncated solid tile");
        for (size_t i = 0; i < total; ++i) put(i, c);
      } else if (sub <= 16) {
        for (int i = 0; i < sub; ++i) {
          if (!cpixel(palette[i])) return fail(error, "ZRLE: truncated palette");
        }
        const int bits = sub == 2 ? 1 : sub <= 4 ? 2 : 4;
        const size_t stride = (size_t(tw) * bits + 7) / 8;
        if (pos + stride * th > n) return fail(error, "ZRLE: truncated packed tile");
        for (int y = 0; y < th; ++y) {
          const uint8_t* rowp = s + pos + y * stride;
          for (int x = 0; x < tw; ++x) {
            const int bit = x * bits;
            const int idx = (rowp[bit >> 3] >> (8 - bits - (bit & 7))) & ((1 << bits) - 1);
            if (idx >= sub) return fail(error, "ZRLE: palette index out of range");
            put(size_t(y) * tw + x, palette[idx]);
          }
        }
        pos += stride * th;
      } else if (sub == 128) {
        for (size_t i = 0; i < total;) {
          uint32_t c;
          size_t len;
          if (!cpixel(c) || !run_length(len)) return fail(error, "ZRLE: truncated run");
          if (i + len > total) return fail(error, "ZRLE: run past the tile");
          for (size_t k = 0; k < len; ++k) put(i++, c);
        }
      } else if (sub >= 130) {
        const int size = sub - 128;
        for (int i = 0; i < size; ++i) {
          if (!cpixel(palette[i])) return fail(error, "ZRLE: truncated palette");
        }
        for (size_t i = 0; i < total;) {
          uint8_t idx;
          size_t len = 1;
          if (!byte(idx) || ((idx & 128) && !run_length(len))) return fail(error, "ZRLE: truncated palette run");
          if ((idx & 127) >= size) return fail(error, "ZRLE: palette index out of range");
          if (i + len > total) return fail(error, "ZRLE: run past the tile");
          for (size_t k = 0; k < len; ++k) put(i++, palette[idx & 127]);
        }
      } else {
        return fail(error, std::format("ZRLE: unknown subencoding {}", sub));
      }
    }
  }
  return true;
}

}  // namespace iss::session
