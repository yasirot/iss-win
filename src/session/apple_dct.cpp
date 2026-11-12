#include "session/apple_dct.h"

#include <algorithm>
#include <cstring>
#include <format>
#include <stdexcept>

#include "core/bytes.h"

namespace iss::session {
namespace {

struct Malformed : std::runtime_error {
  using std::runtime_error::runtime_error;
};

constexpr int kZigzag[64] = {0,  1,  8,  16, 9,  2,  3,  10, 17, 24, 32, 25, 18, 11, 4,  5,
                             12, 19, 26, 33, 40, 48, 41, 34, 27, 20, 13, 6,  7,  14, 21, 28,
                             35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51,
                             58, 59, 52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63};

// ホストがテーブルを送ってくるまでの既定値（自然順）。
constexpr uint8_t kDefaultLuma[64] = {16, 11, 11, 14, 24, 22, 24, 33, 11, 12, 11, 11, 26, 18, 19, 23,
                                      13, 13, 14, 24, 20, 21, 22, 28, 13, 17, 14, 21, 23, 25, 34, 34,
                                      17, 22, 18, 25, 31, 32, 34, 44, 24, 20, 17, 27, 35, 40, 44, 54,
                                      30, 35, 28, 30, 34, 44, 54, 64, 35, 30, 33, 38, 45, 55, 65, 75};
constexpr uint8_t kDefaultChroma[64] = {19, 19, 24, 47, 76, 99, 99, 99, 19, 21, 26, 66, 99, 99, 99, 99,
                                        24, 26, 56, 99, 99, 99, 99, 99, 47, 66, 99, 99, 99, 99, 99, 99,
                                        76, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
                                        99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99};

// JPEGの輝度ACのハフマンテーブル（符号長ごとのカノニカル符号の数と、シンボル）。
constexpr int kAcCounts[16] = {0, 2, 1, 3, 3, 2, 4, 3, 5, 5, 4, 4, 0, 0, 1, 125};
constexpr uint8_t kAcSymbols[162] = {
    0x01, 0x02, 0x03, 0x00, 0x04, 0x11, 0x05, 0x12, 0x21, 0x31, 0x41, 0x06, 0x13, 0x51, 0x61, 0x07, 0x22, 0x71,
    0x14, 0x32, 0x81, 0x91, 0xa1, 0x08, 0x23, 0x42, 0xb1, 0xc1, 0x15, 0x52, 0xd1, 0xf0, 0x24, 0x33, 0x62, 0x72,
    0x82, 0x09, 0x0a, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3a, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59,
    0x5a, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x83,
    0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0xa2, 0xa3,
    0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xc2, 0xc3,
    0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xe1, 0xe2,
    0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa};

constexpr int kCacheSize = 65000;  // リングのインデックスは1..64999

int next_cache_index(int i) { return i >= kCacheSize - 1 ? 1 : i + 1; }
int8_t clamp8(int v) { return static_cast<int8_t>(std::clamp(v, -128, 127)); }
int16_t clamp16(int v) { return static_cast<int16_t>(std::clamp(v, -32768, 32767)); }
uint8_t clamp_u8(int v) { return static_cast<uint8_t>(std::clamp(v, 0, 255)); }

// stb_imageの固定小数点によるYCbCr → RGB（緑のCbの項は上位ビットだけを残す）。
uint32_t ycbcr(uint8_t y, uint8_t cb_byte, uint8_t cr_byte) {
  const int yf = (int(y) << 20) + (1 << 19);
  const int cb = int(cb_byte) - 128, cr = int(cr_byte) - 128;
  const int r = (yf + cr * (5743 << 8)) >> 20;
  const int green_cb = static_cast<int32_t>(static_cast<uint32_t>(cb * -(1410 << 8)) & 0xffff0000u);
  const int g = (yf + cr * -(2925 << 8) + green_cb) >> 20;
  const int b = (yf + cb * (7258 << 8)) >> 20;
  return 0xff000000u | uint32_t(clamp_u8(r)) << 16 | uint32_t(clamp_u8(g)) << 8 | clamp_u8(b);
}

// stb_imageの整数IDCT（jidctintの"islow"）の1パス。32ビットの桁あふれによる
// 折り返しを明示するため、符号なしで計算する。
struct Idct1d {
  uint32_t t0, t1, t2, t3, x0, x1, x2, x3;
  Idct1d(uint32_t s0, uint32_t s1, uint32_t s2, uint32_t s3, uint32_t s4, uint32_t s5, uint32_t s6, uint32_t s7) {
    uint32_t p1 = (s2 + s6) * 2217;
    t2 = p1 + s6 * uint32_t(-7567);
    t3 = p1 + s2 * 3135;
    t0 = (s0 + s4) * 4096;
    t1 = (s0 - s4) * 4096;
    x0 = t0 + t3;
    x3 = t0 - t3;
    x1 = t1 + t2;
    x2 = t1 - t2;
    t0 = s7;
    t1 = s5;
    t2 = s3;
    t3 = s1;
    uint32_t p3 = t0 + t2, p4 = t1 + t3, p2 = t1 + t2;
    p1 = t0 + t3;
    const uint32_t p5 = (p3 + p4) * 4816;
    t0 *= 1223;
    t1 *= 8410;
    t2 *= 12586;
    t3 *= 6149;
    p1 = p5 + p1 * uint32_t(-3685);
    p2 = p5 + p2 * uint32_t(-10497);
    p3 *= uint32_t(-8034);
    p4 *= uint32_t(-1597);
    t3 += p1 + p4;
    t2 += p2 + p3;
    t1 += p2 + p4;
    t0 += p1 + p3;
  }
};

void idct8x8(uint8_t out[64], const int16_t in[64]) {
  int v[64];
  for (int c = 0; c < 8; ++c) {
    const int16_t* d = in + c;
    int* o = v + c;
    if (!d[8] && !d[16] && !d[24] && !d[32] && !d[40] && !d[48] && !d[56]) {
      for (int r = 0; r < 8; ++r) o[r * 8] = d[0] * 4;
      continue;
    }
    Idct1d k{uint32_t(d[0]), uint32_t(d[8]), uint32_t(d[16]), uint32_t(d[24]), uint32_t(d[32]), uint32_t(d[40]),
             uint32_t(d[48]), uint32_t(d[56])};
    k.x0 += 512;
    k.x1 += 512;
    k.x2 += 512;
    k.x3 += 512;
    o[0] = int32_t(k.x0 + k.t3) >> 10;
    o[56] = int32_t(k.x0 - k.t3) >> 10;
    o[8] = int32_t(k.x1 + k.t2) >> 10;
    o[48] = int32_t(k.x1 - k.t2) >> 10;
    o[16] = int32_t(k.x2 + k.t1) >> 10;
    o[40] = int32_t(k.x2 - k.t1) >> 10;
    o[24] = int32_t(k.x3 + k.t0) >> 10;
    o[32] = int32_t(k.x3 - k.t0) >> 10;
  }
  for (int r = 0; r < 8; ++r) {
    const int* s = v + r * 8;
    Idct1d k{uint32_t(s[0]), uint32_t(s[1]), uint32_t(s[2]), uint32_t(s[3]), uint32_t(s[4]), uint32_t(s[5]),
             uint32_t(s[6]), uint32_t(s[7])};
    constexpr uint32_t kBias = 65536 + (128u << 17);
    k.x0 += kBias;
    k.x1 += kBias;
    k.x2 += kBias;
    k.x3 += kBias;
    uint8_t* o = out + r * 8;
    o[0] = clamp_u8(int32_t(k.x0 + k.t3) >> 17);
    o[7] = clamp_u8(int32_t(k.x0 - k.t3) >> 17);
    o[1] = clamp_u8(int32_t(k.x1 + k.t2) >> 17);
    o[6] = clamp_u8(int32_t(k.x1 - k.t2) >> 17);
    o[2] = clamp_u8(int32_t(k.x2 + k.t1) >> 17);
    o[5] = clamp_u8(int32_t(k.x2 - k.t1) >> 17);
    o[3] = clamp_u8(int32_t(k.x3 + k.t0) >> 17);
    o[4] = clamp_u8(int32_t(k.x3 - k.t0) >> 17);
  }
}

void fill_tile(uint32_t* fb, int fb_w, int fb_h, int x, int y, uint32_t color) {
  for (int r = y; r < std::min(y + 8, fb_h); ++r) {
    std::fill(fb + size_t(r) * fb_w + x, fb + size_t(r) * fb_w + std::min(x + 8, fb_w), color);
  }
}

void put_tile(uint32_t* fb, int fb_w, int fb_h, int x, int y, const uint32_t px[64]) {
  const int cols = std::min(8, fb_w - x);
  for (int r = 0; r < std::min(8, fb_h - y); ++r) {
    std::memcpy(fb + size_t(y + r) * fb_w + x, px + r * 8, size_t(cols) * 4);
  }
}

void copy_tile(uint32_t* fb, int fb_w, int fb_h, int sx, int sy, int dx, int dy) {
  const int cols = std::min(8, fb_w - std::max(sx, dx));
  const int rows = std::min({8, fb_h - sy, fb_h - dy});
  if (sx < 0 || sy < 0 || dx < 0 || dy < 0 || cols <= 0 || rows <= 0) return;
  for (int r = rows - 1; r >= 0; --r) {
    std::memmove(fb + size_t(dy + r) * fb_w + dx, fb + size_t(sy + r) * fb_w + sx, size_t(cols) * 4);
  }
}

}  // namespace

// ビットストリームの1本をMSBから読むリーダー。
class AppleDctDecoder::Bits {
 public:
  Bits(const uint8_t* p, size_t n) : p_(p), n_(n) {}

  uint32_t bit() {
    if (have_ == 0) {
      if (pos_ >= n_) throw Malformed("bitstream ended early");
      buf_ = p_[pos_++];
      have_ = 8;
    }
    --have_;
    return (buf_ >> have_) & 1;
  }
  uint32_t bits(int count) {
    uint32_t v = 0;
    while (count-- > 0) v = v << 1 | bit();
    return v;
  }

  // 0 → タイル1つ。それ以外は4ビットで2..16を表す。ただし15はエスケープで、
  // リトルエンディアンの128進のグループ1〜3個 + 17になる。
  int run_length() {
    if (!bit()) return 1;
    const int s = static_cast<int>(bits(4));
    if (s != 15) return s + 2;
    int ext = 0;
    for (int g = 0; g < 3; ++g) {
      const int b = static_cast<int>(bits(8));
      ext |= (b & 0x7f) << (7 * g);
      if (!(b & 0x80)) break;
    }
    return ext + 17;
  }

  // DCの差分と改良の値に使う、符号付きのRice符号の変種。
  int rice() {
    int prefix = 0;
    while (bit()) {
      if (++prefix >= 40) throw Malformed("Rice prefix too long");
    }
    if (prefix == 0) {
      if (!bit()) return 0;
      return bit() ? -1 : 1;
    }
    int magnitude;
    uint32_t s;
    if (prefix == 1) {
      s = bits(2);
      magnitude = 2 + int(s >> 1);
    } else if (prefix == 2) {
      s = bits(3);
      magnitude = 4 + int(s >> 1);
    } else {
      s = bits(4);
      magnitude = prefix * 8 + int(s >> 1) - 16;
    }
    return s & 1 ? -magnitude : magnitude;
  }

  // 小さい形式に収まらない大きなAC係数。
  int large_coefficient(int index) {
    const int max_prefix = index < 6 ? 34 : 20;
    int prefix = 0;
    while (bit()) {
      if (++prefix >= max_prefix) throw Malformed("AC prefix too long");
    }
    int magnitude;
    uint32_t s;
    if (index < 6) {
      if (prefix <= 3) {
        s = bits(3);
        magnitude = prefix * 4 + int(s >> 1) + 2;
      } else {
        s = bits(4);
        magnitude = prefix * 8 + int(s >> 1) - 14;
      }
    } else if (prefix == 0) {
      s = bits(2);
      magnitude = 2 + int(s >> 1);
    } else if (prefix == 1) {
      s = bits(3);
      magnitude = 4 + int(s >> 1);
    } else {
      s = bits(4);
      magnitude = prefix * 8 + int(s >> 1) - 8;
    }
    return s & 1 ? -magnitude : magnitude;
  }

  // Yは8ビット、CbとCrは6ビットずつで、それぞれのバイトの上位ビットに入る。
  uint32_t color() {
    const auto y = static_cast<uint8_t>(bits(8));
    const auto cb = static_cast<uint8_t>(bits(6) << 2);
    const auto cr = static_cast<uint8_t>(bits(6) << 2);
    return ycbcr(y, cb, cr);
  }

  // 2色。8ビットの行マップ（立っていればその行はすべて`first`）と、それ以外の
  // 行ごとの8ビットのピクセルマスク（立っていれば`first`）。
  void two_color(uint32_t* fb, int fb_w, int fb_h, int x, int y, uint32_t first, uint32_t second) {
    uint32_t rows = bits(8);
    for (int r = 0; r < 8; ++r, rows <<= 1) {
      const bool uniform = rows & 0x80;
      const uint32_t mask = uniform ? 0 : bits(8);
      if (y + r >= fb_h) continue;
      uint32_t* d = fb + size_t(y + r) * fb_w;
      for (int c = 0; c < 8 && x + c < fb_w; ++c) d[x + c] = uniform || (mask & (0x80u >> c)) ? first : second;
    }
  }

 private:
  const uint8_t* p_;
  size_t n_;
  size_t pos_ = 0;
  uint32_t buf_ = 0;
  int have_ = 0;
};

AppleDctDecoder::AppleDctDecoder() {
  for (int i = 0; i < 64; ++i) {
    luma_q_[i] = kDefaultLuma[i];
    chroma_q_[i] = kDefaultChroma[i];
  }
  zero_.quality = 0;
}

AppleDctDecoder::~AppleDctDecoder() = default;

void AppleDctDecoder::ensure_size(int fb_w, int fb_h) {
  if (fb_w == fb_w_ && fb_h == fb_h_) return;
  fb_w_ = fb_w;
  fb_h_ = fb_h;
  const size_t count = size_t((fb_w + 7) / 8) * ((fb_h + 7) / 8);
  tiles_.assign(count, Tile{});
  meta_.assign(count, TileMeta{});
  generation_ = 0;
  cache_.clear();
  cache_write_ = cache_read_ = 0;
}

void AppleDctDecoder::to_pixels(const Tile& t, uint32_t out[64]) const {
  uint8_t planes[3][64];
  bool flat = true;
  for (int p = 0; p < 3; ++p) {
    const auto& q = p == 0 ? luma_q_ : chroma_q_;
    int16_t deq[64];
    int ac = 0;
    for (int i = 0; i < 64; ++i) {
      deq[i] = static_cast<int16_t>(t.values[size_t(p) * 64 + i] * q[i]);
      if (i) ac |= deq[i];
    }
    if (ac == 0) {
      std::memset(planes[p], clamp_u8(((int(deq[0]) + 4) >> 3) + 128), 64);
    } else {
      idct8x8(planes[p], deq);
      flat = false;
    }
  }
  if (flat) {
    std::fill(out, out + 64, ycbcr(planes[0][0], planes[1][0], planes[2][0]));
    return;
  }
  for (int i = 0; i < 64; ++i) out[i] = ycbcr(planes[0][i], planes[1][i], planes[2][i]);
}

const AppleDctDecoder::Tile& AppleDctDecoder::cached(int index) {
  if (index <= 0 || index >= kCacheSize) throw Malformed(std::format("cache index {}", index));
  cache_read_ = index;
  const size_t page = size_t(index) / 256;
  if (page < cache_.size() && cache_[page] && (*cache_[page])[index % 256].quality >= 0) {
    return (*cache_[page])[index % 256];
  }
  return zero_;
}

bool AppleDctDecoder::apply(int x, int y, int w, int h, const uint8_t* payload, size_t n, uint32_t* fb, int fb_w,
                            int fb_h, std::string* error) {
  try {
    if (n < 5) throw Malformed("payload shorter than 5 bytes");
    if (rd_be32(payload) != n - 4) throw Malformed(std::format("length {} for {} bytes", rd_be32(payload), n - 4));
    const uint8_t* msg = payload + 4;
    const size_t len = n - 4;
    if (msg[0] == 2) {
      if (len != 129) throw Malformed(std::format("quantization tables of {} bytes", len));
      for (int i = 0; i < 64; ++i) {
        luma_q_[i] = msg[1 + i];
        chroma_q_[i] = msg[65 + i];
      }
      return true;
    }
    if (msg[0] > 2) throw Malformed(std::format("message type {}", msg[0]));
    if (x < 0 || y < 0 || x + w > fb_w || y + h > fb_h) throw Malformed("rectangle outside the screen");
    ensure_size(fb_w, fb_h);
    if (msg[0] == 0) {
      image(x, y, w, h, msg, len, fb, fb_w, fb_h);
    } else {
      refinement(x, y, w, h, msg, len, fb, fb_w, fb_h);
    }
    return true;
  } catch (const std::exception& e) {
    if (error) *error = std::string("Apple DCT: ") + e.what();
    return false;
  }
}

void AppleDctDecoder::image(int x, int y, int w, int h, const uint8_t* msg, size_t n, uint32_t* fb, int fb_w,
                            int fb_h) {
  if (n < 7) throw Malformed("image message shorter than 7 bytes");
  const size_t data_off = size_t(msg[3]) << 16 | size_t(msg[4]) << 8 | msg[5];
  if (data_off < 6 || data_off >= n) throw Malformed(std::format("data offset {} of {} bytes", data_off, n));
  const int low_cutoff = msg[1], high_cutoff = msg[2];
  Bits cmd(msg + 6, data_off - 6), data(msg + data_off, n - data_off);
  cmd.bit();  // 予約

  const int tw = (w + 7) / 8, count = tw * ((h + 7) / 8);
  const int fb_tw = (fb_w + 7) / 8;
  const uint64_t generation = ++generation_;
  predictor_ = Tile{};
  predictor_.quality = 0;
  uint32_t last[64], pixels[64];
  bool have_last = false;

  for (int tile = 0; tile < count;) {
    const int command = static_cast<int>(cmd.bits(3));
    const int run = std::min(cmd.run_length(), count - tile);
    for (int k = 0; k < run; ++k, ++tile) {
      const int px = x + (tile % tw) * 8, py = y + (tile / tw) * 8;
      const int gi = (py / 8) * fb_tw + px / 8;
      meta_[gi] = {-1, -1, generation};
      switch (command) {
        case 0:
          fill_tile(fb, fb_w, fb_h, px, py, 0xffffffff);
          break;
        case 1: {  // コマンド順で直前のタイル（行の先頭なら上の行の末尾）
          if (tile == 0) throw Malformed("copy of a previous tile at the first tile");
          const int sx = x + ((tile - 1) % tw) * 8, sy = y + ((tile - 1) / tw) * 8;
          copy_tile(fb, fb_w, fb_h, sx, sy, px, py);
          meta_[gi].validation_source = meta_[gi].pixel_source = (sy / 8) * fb_tw + sx / 8;
          break;
        }
        case 2:
          if (py < 8) throw Malformed("copy of the tile above in the top row");
          copy_tile(fb, fb_w, fb_h, px, py - 8, px, py);
          meta_[gi].validation_source = meta_[gi].pixel_source = gi - fb_tw;
          break;
        case 3:
          data.two_color(fb, fb_w, fb_h, px, py, 0xffffffff, 0xff000000);
          break;
        case 4: {
          const uint32_t sub = data.bits(2);
          if (sub <= 1) {
            if (sub == 0) {
              solid_ = data.color();
              have_solid_ = true;
            } else if (!have_solid_) {
              throw Malformed("solid colour reused before it was set");
            }
            fill_tile(fb, fb_w, fb_h, px, py, solid_);
          } else {
            if (sub == 2) {
              first_ = data.color();
              second_ = data.color();
              have_palette_ = true;
            } else if (!have_palette_) {
              throw Malformed("two-colour palette reused before it was set");
            }
            data.two_color(fb, fb_w, fb_h, px, py, first_, second_);
          }
          break;
        }
        case 5: {
          const bool reuse = data.bit();
          if (!reuse) decode_new_tile(data, low_cutoff, high_cutoff);
          Tile& t = tiles_[gi];
          t = predictor_;
          t.cb_count = t.cr_count = 1;
          if (!reuse || !have_last) {
            to_pixels(predictor_, last);
            have_last = true;
          }
          put_tile(fb, fb_w, fb_h, px, py, last);
          break;
        }
        case 6:
        case 7: {
          const int index = command == 6 ? static_cast<int>(data.bits(16)) : next_cache_index(cache_read_);
          to_pixels(cached(index), pixels);
          put_tile(fb, fb_w, fb_h, px, py, pixels);
          break;
        }
      }
    }
  }
}

// 新しいDCTのタイル。輝度DCと色差DCを直前のタイルとの差分で読み、続けて輝度AC
// 係数をジグザグ順に読む。
void AppleDctDecoder::decode_new_tile(Bits& data, int low_cutoff, int high_cutoff) {
  const bool reuse_chroma = data.bit();
  const int cutoff = data.bit() ? high_cutoff : low_cutoff;
  const int prev_y = predictor_.values[0], prev_cb = predictor_.values[64], prev_cr = predictor_.values[128];
  auto& v = predictor_.values;
  auto& m = predictor_.map;
  v.fill(0);
  m.fill(0);
  if (reuse_chroma) {
    v[64] = static_cast<int16_t>(prev_cb);
    v[128] = static_cast<int16_t>(prev_cr);
  } else {
    v[64] = clamp16((prev_cb / 2 - data.rice()) * 2);
    v[128] = clamp16((prev_cr / 2 - data.rice()) * 2);
  }
  v[0] = clamp16(prev_y - data.rice());
  m[0] = static_cast<int8_t>(v[0]);
  m[64] = static_cast<int8_t>(v[64]);
  m[84] = static_cast<int8_t>(v[128]);

  for (int c = 1; c < 64;) {
    const bool low = c < cutoff;
    if (data.bit()) {  // 大きい値
      const auto stored = static_cast<int8_t>(data.large_coefficient(c) << (cutoff < 15 ? (low ? 3 : 4) : (low ? 1 : 3)));
      m[c] = stored;
      v[kZigzag[c]] = stored;
      ++c;
      continue;
    }
    // 小さい値。0、±振幅、ブロックの終わり、0の連続のどれか。
    const int amplitude = cutoff < 15 ? (low ? 8 : 16) : (low ? 2 : 8);
    const uint32_t code = data.bits(2);
    if (code == 0) {
      ++c;
    } else if (code >= 2) {
      const int value = code == 2 ? amplitude : -amplitude;
      v[kZigzag[c]] = static_cast<int16_t>(value);
      m[c] = static_cast<int8_t>(value);
      ++c;
    } else if (!data.bit()) {
      break;  // ブロックの終わり
    } else if (const int skip = static_cast<int>(data.bits(2)); skip != 3) {
      c += skip + 3;
    } else {
      int run = 6;
      for (int g = 7; g == 7;) {
        g = static_cast<int>(data.bits(3));
        run += g;
      }
      if (c + run >= 64) throw Malformed("zero run past coefficient 63");
      c += run;
    }
  }
  predictor_.quality = cutoff;
}

void AppleDctDecoder::refinement(int x, int y, int w, int h, const uint8_t* msg, size_t n, uint32_t* fb, int fb_w,
                                 int fb_h) {
  if (n < 3) throw Malformed("refinement message shorter than 3 bytes");
  const int threshold1 = msg[1], threshold2 = msg[2];
  if (threshold1 >= 16 || threshold2 >= 21) throw Malformed(std::format("refinement thresholds {},{}", threshold1, threshold2));
  Bits bits(msg + 3, n - 3);
  const int tw = (w + 7) / 8, count = tw * ((h + 7) / 8);
  const int fb_tw = (fb_w + 7) / 8;
  uint32_t pixels[64];
  for (int tile = 0; tile < count; ++tile) {
    const int px = x + (tile % tw) * 8, py = y + (tile / tw) * 8;
    const int gi = (py / 8) * fb_tw + px / 8;
    switch (bits.bits(2)) {
      case 1: {  // このタイルを改良する。結果はキャッシュのリングにも入れる
        if (tiles_[gi].quality < 0) throw Malformed(std::format("refinement of tile {} without coefficients", gi));
        const Tile t = refine(tiles_[gi], bits, threshold1, threshold2);
        cache_write_ = next_cache_index(cache_write_);
        const size_t page = size_t(cache_write_) / 256;
        if (cache_.size() <= page) cache_.resize(page + 1);
        if (!cache_[page]) cache_[page] = std::make_unique<std::array<Tile, 256>>();  // quality -1は空
        (*cache_[page])[cache_write_ % 256] = t;
        tiles_[gi] = t;
        to_pixels(t, pixels);
        put_tile(fb, fb_w, fb_h, px, py, pixels);
        break;
      }
      case 2: {  // 元の更新で行ったコピーを、コピー元が同じ更新のものならもう一度行う
        const TileMeta& m = meta_[gi];
        if (m.validation_source >= 0 && m.pixel_source >= 0 && meta_[m.validation_source].generation == m.generation) {
          copy_tile(fb, fb_w, fb_h, (m.pixel_source % fb_tw) * 8, (m.pixel_source / fb_tw) * 8, px, py);
        }
        break;
      }
      case 3: {
        const int index = bits.bit() ? next_cache_index(cache_read_) : static_cast<int>(bits.bits(16));
        to_pixels(cached(index), pixels);
        put_tile(fb, fb_w, fb_h, px, py, pixels);
        break;
      }
      default:
        break;
    }
  }
}

// タイルの前の係数に、輝度ACの追加、色差DCの補正、色差AC（JPEGと同じ形の
// ハフマン符号）を重ねる。
AppleDctDecoder::Tile AppleDctDecoder::refine(const Tile& old, Bits& bits, int threshold1, int threshold2) {
  if (old.cb_count != 1 || old.cr_count != 1) throw Malformed("refinement of a tile that already has chroma AC");
  auto adjust_by_one = [&](int8_t c) -> int8_t {
    const int a = static_cast<int>(bits.bit());
    if (c > 0) return clamp8(c + a);
    if (c < 0) return clamp8(c - a);
    if (!a) return 0;
    return bits.bit() ? -1 : 1;
  };
  auto adjust_or_read = [&](int8_t c, int width) -> int8_t {
    if (c == 0) return clamp8(bits.rice());
    const int a = static_cast<int>(bits.bits(width));
    return clamp8(c + (c < 0 ? -a : a));
  };
  auto huffman = [&](std::array<int8_t, 99>& map, int base, int maximum) {
    for (int c = 1; c <= maximum;) {
      int code = 0, first = 0, index = 0, symbol = -1;
      for (int len = 1; len <= 16; ++len) {
        code = code << 1 | static_cast<int>(bits.bit());
        const int count = kAcCounts[len - 1];
        if (code - first >= 0 && code - first < count) {
          symbol = kAcSymbols[index + code - first];
          break;
        }
        index += count;
        first = (first + count) << 1;
      }
      if (symbol < 0) throw Malformed("bad refinement Huffman code");
      const int zeros = symbol >> 4, size = symbol & 15;
      if (size == 0) {
        if (zeros != 15) return;  // ブロックの終わり
        c += 16;
        continue;
      }
      c += zeros;
      int amplitude = static_cast<int>(bits.bits(size));
      if (amplitude < (1 << (size - 1))) amplitude -= (1 << size) - 1;
      if (base + c < 99) map[base + c] = clamp8(amplitude);
      ++c;
    }
  };

  Tile t;
  t.map.fill(0);
  t.map[0] = old.map[0];
  const int target = static_cast<int>(bits.bits(6));
  int next = std::min(old.quality, target + 1);
  if (old.quality > 14) {
    if (target == 0) {
      next = 1;
    } else if (next >= 2) {
      for (int c = 1; c < next; ++c) t.map[c] = adjust_by_one(old.map[c]);
    }
    for (int c = next; c <= target && c < 64; ++c) t.map[c] = adjust_or_read(old.map[c], 3);
  } else {
    if (next >= 2) {
      for (int c = 1; c < next; ++c) t.map[c] = adjust_or_read(old.map[c], 3);
    } else {
      next = 1;
    }
    for (int c = next; c <= target && c < 64; ++c) t.map[c] = adjust_or_read(old.map[c], 4);
  }
  t.map[84] = adjust_by_one(old.map[84]);
  huffman(t.map, 84, threshold1);
  t.map[64] = adjust_by_one(old.map[64]);
  huffman(t.map, 64, threshold2);

  t.values.fill(0);
  for (int c = 0; c < 64; ++c) t.values[kZigzag[c]] = t.map[c];
  for (int c = 0; c < 20; ++c) t.values[64 + kZigzag[c]] = t.map[64 + c];
  for (int c = 0; c < 15; ++c) t.values[128 + kZigzag[c]] = t.map[84 + c];
  t.quality = std::min(64, target + 1);
  t.cb_count = static_cast<uint8_t>(threshold2 + 1);
  t.cr_count = static_cast<uint8_t>(threshold1 + 1);
  return t;
}

}  // namespace iss::session
