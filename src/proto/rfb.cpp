#include "proto/rfb.h"

#include <algorithm>
#include <stdexcept>

namespace iss::rfb {

std::array<uint8_t, 32> apple_viewer_command_mask() {
  std::array<uint8_t, 32> m{};
  m[0] = 0xb0;
  m[2] = 0x0c;
  m[3] = 0x03;
  m[4] = 0x90;
  m[10] = 0x40;
  return m;
}

Bytes apple_0x12_followup() {
  // >BBHHHI: 種別0x12、パディング、A=1、B=1、C=1、末尾=1
  return ByteWriter().u8(0x12).u8(0).be16(1).be16(1).be16(1).be32(1).take();
}

Bytes build_set_encodings(const std::vector<int32_t>& encodings) {
  ByteWriter w;
  w.u8(CLI_SET_ENCODINGS).u8(0).be16(static_cast<uint16_t>(encodings.size()));
  for (int32_t e : encodings) w.be32(static_cast<uint32_t>(e));
  return w.take();
}

Bytes build_post_encryption_toggle() { return from_hex("1200000200010000"); }

Bytes build_key_event(bool down, uint32_t keysym) {
  return ByteWriter().u8(CLI_KEY_EVENT).u8(down ? 1 : 0).zeros(2).be32(keysym).take();
}

Bytes build_pointer_event(uint8_t buttons, int x, int y) {
  auto clamp16 = [](int v) { return static_cast<uint16_t>(std::clamp(v, 0, 0xFFFF)); };
  return ByteWriter().u8(CLI_POINTER_EVENT).u8(buttons).be16(clamp16(x)).be16(clamp16(y)).take();
}

Bytes build_viewer_info(uint32_t app_id, std::array<uint32_t, 3> app_ver, std::array<uint32_t, 3> os_ver,
                        const std::array<uint8_t, 32>& command_mask, const Bytes& extra) {
  ByteWriter w;
  w.u8(CLI_VIEWER_INFO).u8(0);
  w.be16(static_cast<uint16_t>(0x3E + extra.size()));  // msgSizeフィールドより後ろのバイト数
  w.be16(1);                                           // msgVersion
  w.be32(app_id);
  for (uint32_t v : app_ver) w.be32(v);
  for (uint32_t v : os_ver) w.be32(v);
  w.raw(command_mask.data(), command_mask.size());
  w.bytes(extra);
  return w.take();
}

Bytes build_default_viewer_info_with_followup() {
  Bytes out = build_viewer_info(2, {6, 1, 0}, kAppleViewerOsVer, apple_viewer_command_mask());
  Bytes f = apple_0x12_followup();
  out.insert(out.end(), f.begin(), f.end());
  return out;
}

namespace {

// ディスプレイディスクリプタ1つ（§7.1、オフセットは先頭から）。
Bytes display_descriptor(const VirtualDisplayParams& p) {
  const size_t di_size = 0x9C + 28 * static_cast<size_t>(p.mode_count);
  Bytes di(di_size, 0);
  wr_be16(&di[0x00], static_cast<uint16_t>(di_size));
  // 名前の領域は+0x02..+0x79。+0x79にNULが入るよう119バイトで切る。
  size_t name_len = std::min<size_t>(p.display_name.size(), 119);
  std::copy_n(p.display_name.data(), name_len, di.begin() + 0x02);

  auto put_f32 = [&](size_t off, float v) { uint32_t u; std::memcpy(&u, &v, 4); wr_be32(&di[off], u); };
  auto put_f64 = [&](size_t off, double v) { uint64_t u; std::memcpy(&u, &v, 8); wr_be64(&di[off], u); };

  wr_be32(&di[0x7A], 1);  // display_flags = DYNAMIC_RESOLUTION
  wr_be32(&di[0x7E], 4);  // display_type = 仮想ディスプレイ
  put_f32(0x82, 369.4545593261719f);  // 物理サイズ（mm）。純正クライアントの通信をキャプチャした値
  put_f32(0x86, 207.81817626953125f);
  wr_be16(&di[0x92], 0);  // current_mode_index
  wr_be16(&di[0x94], 0);  // preferred_mode_index
  wr_be32(&di[0x96], 7);  // 予約。純正クライアントは7を送る（下位バイト = +0x99の"alt-user"ヒント）
  wr_be16(&di[0x9A], static_cast<uint16_t>(p.mode_count));

  struct Mode { int pw, ph, sw, sh; };
  static const Mode kNativeModes[] = {
      {3840, 2160, 1920, 1080}, {2880, 1800, 1440, 900}, {3840, 2160, 1920, 1080},
      {2880, 1620, 1440, 810},  {2624, 1696, 1312, 848},
  };
  const double sx = p.width ? p.width / 1920.0 : 1.0;
  const double sy = p.height ? p.height / 1080.0 : 1.0;
  const uint32_t mode_flags = p.hdr ? 1 : 0;
  for (int i = 0; i < p.mode_count; ++i) {
    const Mode& base = kNativeModes[i % 5];
    // ポイント寸法を目標サイズに合わせ、ピクセル（バッキング）寸法 = ポイント × scale。
    int msw = static_cast<int>(base.sw * sx + 0.5);
    int msh = static_cast<int>(base.sh * sy + 0.5);
    int mw = static_cast<int>(msw * p.hidpi_scale + 0.5);
    int mh = static_cast<int>(msh * p.hidpi_scale + 0.5);
    size_t m = 0x9C + 28 * static_cast<size_t>(i);
    wr_be32(&di[m + 0x00], static_cast<uint32_t>(mw));
    wr_be32(&di[m + 0x04], static_cast<uint32_t>(mh));
    wr_be32(&di[m + 0x08], static_cast<uint32_t>(msw));
    wr_be32(&di[m + 0x0C], static_cast<uint32_t>(msh));
    put_f64(m + 0x10, 60.0);
    wr_be32(&di[m + 0x18], mode_flags);
  }
  // 3840×2160を超えるとMacは小さな代替ディスプレイを返す。maxを上げると
  // ディスプレイは作られるがH.264が始まらない（4320x2324で試した）。
  wr_be32(&di[0x8A], static_cast<uint32_t>(p.max_width));
  wr_be32(&di[0x8E], static_cast<uint32_t>(p.max_height));
  return di;
}

}  // namespace

Bytes build_virtual_display(const VirtualDisplayParams& p, const VirtualDisplayParams* second) {
  const Bytes first = display_descriptor(p);
  Bytes other;
  if (second) {
    VirtualDisplayParams q = *second;
    if (q.display_name == p.display_name) q.display_name += " 2";
    other = display_descriptor(q);
  }
  ByteWriter w;
  w.u8(CLI_VIRTUAL_DISPLAY).u8(0).be16(static_cast<uint16_t>(8 + first.size() + other.size()));
  w.be16(1).be16(second ? 2 : 1).be32(0);
  w.bytes(first).bytes(other);
  return w.take();
}

Bytes build_fbu_request(bool incremental, uint16_t x, uint16_t y, uint16_t w, uint16_t h) {
  return ByteWriter().u8(0x03).u8(incremental ? 1 : 0).be16(x).be16(y).be16(w).be16(h).take();
}

Bytes build_auto_fbu(uint16_t x, uint16_t y, uint16_t w, uint16_t h, uint32_t screen) {
  return ByteWriter().u8(0x09).u8(0).be16(1).be32(screen).be16(x).be16(y).be16(w).be16(h).take();
}

bool parse_apple_display_layout(const uint8_t* p, size_t n, DisplayLayout& out) {
  // ヘッダー20B: ver u16 | scaled_w/h u16 | backing_w/h u16 | 0xffffffff | field u32 | count u16
  // ディスプレイごとに56B: hscale f64 | vscale f64 | id u32 | point rect y0,x0,y1,x1 |
  //                        pixel rect y0,x0,y1,x1 | 末尾の20B
  if (n < 20) return false;
  out = {};
  out.backing_w = rd_be16(p + 6);
  out.backing_h = rd_be16(p + 8);
  const uint16_t count = rd_be16(p + 18);
  constexpr size_t kEntry = 56;
  size_t off = 20;
  for (uint16_t i = 0; i < count && off + kEntry <= n; ++i, off += kEntry) {
    uint32_t did = rd_be32(p + off + 16);
    // グローバルなポイント座標は符号つき。メインより左にあるディスプレイは
    // xが負から始まる。
    auto s16 = [&](size_t at) { return static_cast<int>(static_cast<int16_t>(rd_be16(p + off + at))); };
    int vy0 = s16(20), vx0 = s16(22), vy1 = s16(24), vx1 = s16(26);
    int py0 = rd_be16(p + off + 28), px0 = rd_be16(p + off + 30);
    int py1 = rd_be16(p + off + 32), px1 = rd_be16(p + off + 34);
    if (px1 > px0 && py1 > py0) {
      out.rects.push_back({did, px0, py0, px1 - px0, py1 - py0, vx0, vy0, vx1 - vx0, vy1 - vy0});
    }
  }
  return !out.rects.empty();
}

}  // namespace iss::rfb
