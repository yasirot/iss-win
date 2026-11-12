#include "session/control_messages.h"

#include <algorithm>

#include "core/log.h"
#include "proto/rfb.h"
#include "util/zlib.h"

namespace iss::session {
namespace {

constexpr int32_t kEncCursor = 1104;
constexpr int32_t kEncDisplayLayout = 0x451;
constexpr int32_t kEncDesktopSize = -223;
constexpr int32_t kSkippedEncodings[] = {1010, 1011, 1107, 1109, 1110, 0x3ea, 0x3f2, 0x3f3, 0x453, 0x455, 0x456};
// 標準モード。u32の長さ + ペイロード。
constexpr int32_t kLengthPrefixedPixels[] = {6, 16, 1000, 1001, 1002, 1011};
// u16の長さ + ペイロード。どちらのモードでも。
constexpr int32_t kBlobEncodings[] = {1010, 1107, 1109, 1110, 0x451};
constexpr int32_t kEmptyEncodings[] = {kEncDesktopSize, 1100, 1101};
constexpr int kMaxCursorSide = 1024;

template <size_t N>
bool one_of(const int32_t (&list)[N], int32_t e) {
  return std::find(std::begin(list), std::end(list), e) != std::end(list);
}

enum class Size { Known, NeedMore, Unknown };

// ヘッダのあとの`n`バイトから、1つの矩形のペイロードのバイト数を求める。
Size rect_payload(int32_t enc, int w, int h, const uint8_t* p, size_t n, bool framebuffer, size_t& size) {
  auto prefixed = [&](size_t field, uint32_t len) {
    size = field + len;
    return Size::Known;
  };
  if (enc == kEncCursor) {
    if (n < 8) return Size::NeedMore;
    return prefixed(8, rd_be32(p + 4));
  }
  if (framebuffer) {
    if (enc == 0) return prefixed(0, static_cast<uint32_t>(w) * static_cast<uint32_t>(h) * 4);
    if (enc == 1) return prefixed(0, 4);
    if (one_of(kLengthPrefixedPixels, enc)) {
      if (n < 4) return Size::NeedMore;
      return prefixed(4, rd_be32(p));
    }
    if (one_of(kEmptyEncodings, enc)) return prefixed(0, 0);
    if (!one_of(kBlobEncodings, enc)) return Size::Unknown;
  } else if (enc != kEncDisplayLayout && !one_of(kSkippedEncodings, enc)) {
    return Size::Unknown;
  }
  if (n < 2) return Size::NeedMore;
  return prefixed(2, rd_be16(p));
}

}  // namespace

size_t fbu_length(const uint8_t* p, size_t n) {
  if (n < 4) return 0;
  const uint16_t n_rects = rd_be16(p + 2);
  size_t off = 4;
  for (uint16_t i = 0; i < n_rects; ++i) {
    if (off + 12 > n) return 0;
    const int w = rd_be16(p + off + 4), h = rd_be16(p + off + 6);
    const auto enc = static_cast<int32_t>(rd_be32(p + off + 8));
    off += 12;
    size_t size = 0;
    switch (rect_payload(enc, w, h, p + off, n - off, true, size)) {
      case Size::NeedMore: return 0;
      case Size::Unknown: return kUnknownLength;
      case Size::Known: break;
    }
    off += size;
  }
  return off <= n ? off : 0;
}

CursorRef CursorCache::get(uint32_t id) const {
  auto it = shapes_.find(id);
  return it == shapes_.end() ? nullptr : it->second;
}

void CursorCache::put(uint32_t id, CursorRef shape) {
  if (!shapes_.count(id)) order_.push_back(id);
  shapes_[id] = std::move(shape);
  while (shapes_.size() > kMax) {
    shapes_.erase(order_.front());
    order_.pop_front();
  }
}

FbuEvents parse_fbu(const Bytes& msg, CursorCache& cache, bool framebuffer) {
  FbuEvents ev;
  if (msg.size() < 4 || msg[0] != 0x00) return ev;
  const size_t n = msg.size();
  const uint16_t n_rects = rd_be16(&msg[2]);
  size_t off = 4;
  for (uint16_t i = 0; i < n_rects; ++i) {
    if (off + 12 > n) {
      ev.truncated = true;
      return ev;
    }
    const uint16_t f0 = rd_be16(&msg[off]), f1 = rd_be16(&msg[off + 2]);
    const uint16_t f2 = rd_be16(&msg[off + 4]), f3 = rd_be16(&msg[off + 6]);
    const auto enc = static_cast<int32_t>(rd_be32(&msg[off + 8]));
    off += 12;
    ev.encodings.push_back(enc);
    // 未知のエンコーディング（RFB上のビデオや、知らない疑似エンコーディング）は
    // サイズが分からないので、それより後ろは解析できない。
    size_t size = 0;
    if (rect_payload(enc, f2, f3, &msg[off], n - off, framebuffer, size) != Size::Known || off + size > n) {
      ev.truncated = true;
      return ev;
    }
    const uint8_t* body = &msg[off];
    off += size;

    if (enc == kEncCursor) {
      const uint32_t cache_id = rd_be32(body), comp = rd_be32(body + 4);
      if (comp == 0) {
        ev.cursors.push_back(cache.get(cache_id));
        continue;
      }
      const int w = f2, h = f3;
      const size_t px = size_t(w) * h;
      if (w > 0 && h > 0 && w <= kMaxCursorSide && h <= kMaxCursorSide) {
        auto raw = zlib::decompress_sync_flushed(body + 8, comp, px * 5);
        if (raw && raw->size() == px * 5) {
          auto shape = std::make_shared<CursorShape>();
          shape->width = w;
          shape->height = h;
          shape->hot_x = std::min<int>(f0, w - 1);
          shape->hot_y = std::min<int>(f1, h - 1);
          shape->bgra.assign(raw->begin(), raw->begin() + static_cast<std::ptrdiff_t>(px * 4));
          for (size_t p = 0; p < px; ++p) shape->bgra[p * 4 + 3] = (*raw)[px * 4 + p];
          cache.put(cache_id, shape);
          ev.cursors.push_back(std::move(shape));
        } else {
          log::debug("cursor {}x{} (cache id {}): could not unpack {} B", w, h, cache_id, comp);
        }
      }
    } else if (enc == kEncDisplayLayout) {
      const size_t len = size - 2;
      DisplayLayoutInfo info;
      if (len >= 10) {
        info.scaled_w = rd_be16(body + 4);
        info.scaled_h = rd_be16(body + 6);
        info.backing_w = rd_be16(body + 8);
        info.backing_h = rd_be16(body + 10);
      }
      if (rfb::DisplayLayout layout; rfb::parse_apple_display_layout(body + 2, len, layout)) {
        info.displays = layout.rects.size();
        info.rects = std::move(layout.rects);
      }
      ev.layout = info;
    } else if (framebuffer && enc == kEncDesktopSize) {
      ev.desktop_size = std::make_pair(int(f2), int(f3));
    } else if (framebuffer && (enc == 0 || enc == 1 || one_of(kLengthPrefixedPixels, enc))) {
      ev.pixels.push_back({f0, f1, f2, f3, enc, body, size});
    }
  }
  return ev;
}

}  // namespace iss::session
