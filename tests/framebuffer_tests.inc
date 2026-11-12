// 標準モード。分割したzlib、フレームバッファのデコーダ、更新の区切り。
// test_main.cppから読み込む。

#include "session/framebuffer.h"

// iss-tests --decode-dump DUMP W H OUT.bmp。iss-winの
// --dump-recordsが書いたファイルを標準モードのデコーダで再生し、
// 最後の画面を書き出す（記録の解析用で、ネットワークは使わない）。
int decode_dump(const char* path, int w, int h, const char* out_path) {
  FILE* f = nullptr;
  if (fopen_s(&f, path, "rb") || !f) {
    std::fprintf(stderr, "cannot open %s\n", path);
    return 2;
  }
  Bytes all;
  for (uint8_t buf[65536]; size_t n = std::fread(buf, 1, sizeof(buf), f);) all.insert(all.end(), buf, buf + n);
  std::fclose(f);

  session::Framebuffer fb;
  fb.resize(w, h);
  session::CursorCache cache;
  size_t rects = 0, failed = 0, updates = 0;
  auto handle = [&](const Bytes& msg) {
    if (msg.empty() || msg[0] != 0) return;
    ++updates;
    const session::FbuEvents ev = session::parse_fbu(msg, cache, true);
    if (ev.layout && ev.layout->backing_w > 0 &&
        (ev.layout->backing_w != fb.width() || ev.layout->backing_h != fb.height())) {
      fb.resize(ev.layout->backing_w, ev.layout->backing_h);
    }
    for (const session::PixelRect& r : ev.pixels) {
      ++rects;
      std::string why;
      if (!fb.apply(r, &why) && ++failed <= 10) {
        std::printf("update %zu: %dx%d at %d,%d enc %d: %s\n", updates, r.w, r.h, r.x, r.y, r.encoding, why.c_str());
      }
    }
  };
  Bytes pending;
  for (size_t off = 0; off + 4 <= all.size();) {
    uint32_t n = 0;
    std::memcpy(&n, &all[off], 4);
    off += 4;
    const Bytes rec(all.begin() + static_cast<std::ptrdiff_t>(off),
                    all.begin() + static_cast<std::ptrdiff_t>(std::min(all.size(), off + n)));
    off += n;
    if (pending.empty() && (rec.empty() || rec[0] != 0)) continue;
    pending.insert(pending.end(), rec.begin(), rec.end());
    for (;;) {
      const size_t len = session::fbu_length(pending.data(), pending.size());
      if (len == 0) break;
      if (len == session::kUnknownLength) {
        handle(pending);
        pending.clear();
        break;
      }
      handle(Bytes(pending.begin(), pending.begin() + static_cast<std::ptrdiff_t>(len)));
      pending.erase(pending.begin(), pending.begin() + static_cast<std::ptrdiff_t>(len));
      if (pending.empty() || pending[0] != 0) {
        pending.clear();
        break;
      }
    }
  }
  std::printf("%zu updates, %zu pixel rectangles, %zu failed; screen %dx%d\n", updates, rects, failed, fb.width(),
              fb.height());

  BITMAPFILEHEADER fh{};
  BITMAPINFOHEADER ih{};
  const uint32_t row = uint32_t(fb.width()) * 4;
  fh.bfType = 0x4D42;
  fh.bfOffBits = sizeof(fh) + sizeof(ih);
  fh.bfSize = fh.bfOffBits + row * uint32_t(fb.height());
  ih.biSize = sizeof(ih);
  ih.biWidth = fb.width();
  ih.biHeight = -fb.height();
  ih.biPlanes = 1;
  ih.biBitCount = 32;
  ih.biCompression = BI_RGB;
  FILE* o = nullptr;
  if (fopen_s(&o, out_path, "wb") || !o) return 2;
  std::fwrite(&fh, sizeof(fh), 1, o);
  std::fwrite(&ih, sizeof(ih), 1, o);
  std::fwrite(fb.pixels(), 4, size_t(fb.width()) * fb.height(), o);
  std::fclose(o);
  return failed ? 1 : 0;
}

namespace {

// stored blockをsync flushした1チャンク（deflateのlevel 0が送る形）。
// zlibヘッダは最初のチャンクにだけ付け、最後にZ_SYNC_FLUSHの空の
// stored blockを置く。
Bytes stored_chunk(const Bytes& data, bool header) {
  ByteWriter w;
  if (header) w.u8(0x78).u8(0x01);
  for (size_t pos = 0; pos < data.size();) {
    const size_t len = std::min<size_t>(data.size() - pos, 65535);
    w.u8(0).le16(static_cast<uint16_t>(len)).le16(static_cast<uint16_t>(~len));
    w.raw(data.data() + pos, len);
    pos += len;
  }
  w.u8(0).le16(0).le16(0xFFFF);
  return w.take();
}

// ペイロードがu32の長さ + `chunk` のピクセル矩形。
struct OwnedRect {
  Bytes payload;
  session::PixelRect rect(int x, int y, int w, int h, int32_t enc) const {
    return {x, y, w, h, enc, payload.data(), payload.size()};
  }
};
OwnedRect prefixed(const Bytes& chunk) {
  OwnedRect r;
  r.payload = ByteWriter().be32(static_cast<uint32_t>(chunk.size())).bytes(chunk).take();
  return r;
}

uint32_t px(const session::Framebuffer& fb, int x, int y) { return fb.pixels()[size_t(y) * fb.width() + x]; }

}  // namespace

TEST(zlib_inflater_python_sync_flushed_chunks) {
  FILE* f = nullptr;
  fopen_s(&f, ISS_TEST_DATA_DIR "/zlib_chunks.bin", "rb");
  CHECK(f != nullptr);
  if (!f) return;
  auto u32 = [&] {
    uint32_t v = 0;
    std::fread(&v, 4, 1, f);
    return v;
  };
  auto bytes = [&](uint32_t n) {
    Bytes b(n);
    if (n) std::fread(b.data(), 1, n, f);
    return b;
  };
  const uint32_t streams = u32();
  CHECK(streams == 3);
  for (uint32_t s = 0; s < streams; ++s) {
    zlib::Inflater z;
    const uint32_t chunks = u32();
    for (uint32_t c = 0; c < chunks; ++c) {
      const Bytes comp = bytes(u32());
      const Bytes plain = bytes(u32());
      Bytes out;
      CHECK(z.inflate(comp.data(), comp.size(), out));
      CHECK(out == plain);
    }
  }
  std::fclose(f);
}

TEST(zlib_inflater_rejects_corruption_and_stays_failed) {
  zlib::Inflater z;
  Bytes out;
  const Bytes bad = {0x78, 0x01, 0x07, 0xFF};  // BTYPE 3は予約済み
  CHECK(!z.inflate(bad.data(), bad.size(), out));
  const Bytes good = stored_chunk({1, 2, 3}, true);
  CHECK(!z.inflate(good.data(), good.size(), out));  // reset()するまで失敗のまま
  z.reset();
  CHECK(z.inflate(good.data(), good.size(), out) && out == Bytes({1, 2, 3}));
  CHECK(zlib::looks_like_zlib_header(good.data(), good.size()));
  CHECK(!zlib::looks_like_zlib_header(bad.data() + 2, 2));
}

TEST(fb_apple_legacy_codecs) {
  session::Framebuffer fb;
  fb.resize(4, 2);
  // 1002はビッグエンディアンのx555。白、赤、緑、青の順。
  const OwnedRect thousands = prefixed(stored_chunk({0x7F, 0xFF, 0x7C, 0x00, 0x03, 0xE0, 0x00, 0x1F}, true));
  std::string why;
  CHECK(fb.apply(thousands.rect(0, 0, 4, 1, 1002), &why));
  CHECK(px(fb, 0, 0) == 0xFFFFFFFF && px(fb, 1, 0) == 0xFFFF0000 && px(fb, 2, 0) == 0xFF00FF00 &&
        px(fb, 3, 0) == 0xFF0000FF);
  // 1001は4ビットのグレー。行はバイト境界まで埋める（3ピクセル → 2バイト）。
  const OwnedRect grays = prefixed(stored_chunk({0x0F, 0x80}, true));
  CHECK(fb.apply(grays.rect(0, 1, 3, 1, 1001), &why));
  CHECK(px(fb, 0, 1) == 0xFF000000 && px(fb, 1, 1) == 0xFFFFFFFF && px(fb, 2, 1) == 0xFF888888);
  // 1000は1ビットでMSBから並び、1が白。
  const OwnedRect bw = prefixed(stored_chunk({0xA0}, true));
  CHECK(fb.apply(bw.rect(1, 0, 3, 1, 1000), &why));
  CHECK(px(fb, 1, 0) == 0xFFFFFFFF && px(fb, 2, 0) == 0xFF000000 && px(fb, 3, 0) == 0xFFFFFFFF);
  // 矩形と大きさが合わないものは拒む。
  const OwnedRect short_rect = prefixed(stored_chunk({0x7F}, true));
  CHECK(!fb.apply(short_rect.rect(0, 0, 1, 1, 1002), &why));
  CHECK(!fb.apply(thousands.rect(2, 0, 4, 1, 1002), &why));  // 画面の外
}

TEST(fb_zlib_stream_runs_across_rectangles) {
  session::Framebuffer fb;
  fb.resize(2, 1);
  const OwnedRect a = prefixed(stored_chunk({0x01, 0x02, 0x03, 0x00}, true));   // B G R X
  const OwnedRect b = prefixed(stored_chunk({0x0A, 0x0B, 0x0C, 0x00}, false));  // 前の続き
  std::string why;
  CHECK(fb.apply(a.rect(0, 0, 1, 1, 6), &why));
  CHECK(fb.apply(b.rect(1, 0, 1, 1, 6), &why));
  CHECK(px(fb, 0, 0) == 0xFF030201 && px(fb, 1, 0) == 0xFF0C0B0A);
  const auto dirty = fb.take_dirty();
  CHECK(dirty.size() == 3);  // リサイズの分と、矩形ごとの分
  CHECK(fb.take_dirty().empty());
}

TEST(fb_raw_and_overlapping_copyrect) {
  session::Framebuffer fb;
  fb.resize(4, 2);
  Bytes raw;
  for (uint8_t v = 1; v <= 8; ++v) raw.insert(raw.end(), {v, 0, 0, 0});
  CHECK(fb.apply({0, 0, 4, 2, 0, raw.data(), raw.size()}));
  const Bytes copy = ByteWriter().be16(0).be16(0).take();  // コピー元は(0,0)
  CHECK(fb.apply({1, 0, 3, 2, 1, copy.data(), copy.size()}));
  CHECK(px(fb, 0, 0) == 0xFF000001 && px(fb, 1, 0) == 0xFF000001 && px(fb, 2, 0) == 0xFF000002 &&
        px(fb, 3, 0) == 0xFF000003);
  CHECK(px(fb, 1, 1) == 0xFF000005 && px(fb, 3, 1) == 0xFF000007);
  const Bytes up = ByteWriter().be16(0).be16(1).take();  // 行1を行0へ。コピー元が下にある
  CHECK(fb.apply({0, 0, 4, 1, 1, up.data(), up.size()}));
  CHECK(px(fb, 0, 0) == 0xFF000005);
}

TEST(fb_zrle_subencodings) {
  session::Framebuffer fb;
  fb.resize(66, 2);
  const uint8_t A[3] = {1, 2, 3}, B[3] = {4, 5, 6};
  ByteWriter t;
  // 64x2のタイル。ただのRLEで、128個の連続が1つ（長さのバイトは127）。
  t.u8(128).raw(A, 3).u8(127);
  // 2x2のタイル。2色のパレットで1ピクセル1ビット、各行は"01"と"10"。
  t.u8(2).raw(A, 3).raw(B, 3).u8(0x40).u8(0x80);
  const OwnedRect first = prefixed(stored_chunk(t.take(), true));
  std::string why;
  CHECK(fb.apply(first.rect(0, 0, 66, 2, 16), &why));
  CHECK(px(fb, 0, 0) == 0xFF030201 && px(fb, 63, 1) == 0xFF030201);
  CHECK(px(fb, 64, 0) == 0xFF030201 && px(fb, 65, 0) == 0xFF060504);
  CHECK(px(fb, 64, 1) == 0xFF060504 && px(fb, 65, 1) == 0xFF030201);
  // 2x2はパレットRLE。Aを2回（連続のバイトは1）、B、Aの順。そのあと同じ
  // ストリームの後続の矩形で、rawの1x1と単色の1x1を送る。
  ByteWriter u;
  u.u8(130).raw(B, 3).raw(A, 3).u8(0x80 | 1).u8(1).u8(0).u8(1);
  const OwnedRect second = prefixed(stored_chunk(u.take(), false));
  CHECK(fb.apply(second.rect(0, 0, 2, 2, 16), &why));
  CHECK(px(fb, 0, 0) == 0xFF030201 && px(fb, 1, 0) == 0xFF030201 && px(fb, 0, 1) == 0xFF060504 &&
        px(fb, 1, 1) == 0xFF030201);
  const OwnedRect raw = prefixed(stored_chunk({0, 7, 8, 9}, false));
  CHECK(fb.apply(raw.rect(5, 1, 1, 1, 16), &why) && px(fb, 5, 1) == 0xFF090807);
  const OwnedRect bad = prefixed(stored_chunk({3}, false));  // subencoding 3にはパレットが要る
  CHECK(!fb.apply(bad.rect(0, 0, 1, 1, 16), &why));
}

// AppleのDCTコーデック（1011）。テスト用メッセージを作る、MSBから書くビットライタ。
struct MsbBits {
  Bytes b;
  int n = 0;
  MsbBits& put(uint32_t v, int bits) {
    for (int i = bits - 1; i >= 0; --i, ++n) {
      if (n % 8 == 0) b.push_back(0);
      if ((v >> i) & 1) b.back() |= static_cast<uint8_t>(0x80 >> (n % 8));
    }
    return *this;
  }
};

// type 0の画像メッセージ。カットオフ、データのオフセット、2本のビットストリームを並べる。
OwnedRect dct_image(const MsbBits& cmd, const MsbBits& data, uint8_t low = 15, uint8_t high = 25) {
  const uint32_t data_off = static_cast<uint32_t>(6 + cmd.b.size());
  ByteWriter m;
  m.u8(0).u8(low).u8(high).u8(static_cast<uint8_t>(data_off >> 16)).be16(static_cast<uint16_t>(data_off));
  m.bytes(cmd.b).bytes(data.b);
  return prefixed(m.take());
}

bool near_rgb(uint32_t px, int r, int g, int b) {
  return std::abs(int((px >> 16) & 255) - r) <= 2 && std::abs(int((px >> 8) & 255) - g) <= 2 &&
         std::abs(int(px & 255) - b) <= 2;
}

TEST(apple_dct_fill_copy_and_two_colour) {
  session::Framebuffer fb;
  fb.resize(24, 8);
  // タイル0は単色のYCbCr (107, 164, 124)、1はその複製、2は白黒で行0-6が白、行7が交互。
  MsbBits cmd, data;
  cmd.put(0, 1).put(4, 3).put(0, 1).put(1, 3).put(0, 1).put(3, 3).put(0, 1);
  data.put(0, 2).put(107, 8).put(164 >> 2, 6).put(124 >> 2, 6);
  data.put(0b11111110, 8).put(0b10101010, 8);
  const OwnedRect r = dct_image(cmd, data);
  std::string why;
  CHECK(fb.apply(r.rect(0, 0, 24, 8, 1011), &why));
  CHECK(near_rgb(px(fb, 0, 0), 101, 97, 171) && px(fb, 7, 7) == px(fb, 0, 0));
  CHECK(px(fb, 8, 0) == px(fb, 0, 0) && px(fb, 15, 7) == px(fb, 0, 0));
  CHECK(px(fb, 16, 0) == 0xFFFFFFFF && px(fb, 23, 6) == 0xFFFFFFFF);
  CHECK(px(fb, 16, 7) == 0xFFFFFFFF && px(fb, 17, 7) == 0xFF000000 && px(fb, 23, 7) == 0xFF000000);
}

TEST(apple_dct_dc_tile_quant_tables_and_long_runs) {
  session::Framebuffer fb;
  fb.resize(160, 16);
  // 行0は白いタイル20個の連続1つ（エスケープは1 + 1111 + 値3の128進グループ1つ）。
  // 行1はDC = 8だけのDCTタイル1つ（Riceで-8 → "1110" + "0001"）で、
  // 残りはその複製。
  MsbBits cmd, data;
  cmd.put(0, 1).put(0, 3).put(1, 1).put(15, 4).put(3, 8);
  cmd.put(5, 3).put(0, 1).put(1, 3).put(1, 1).put(15, 4).put(2, 8);
  data.put(0, 1).put(0, 1).put(0, 1);              // 新しいタイル、独自の色差、低いカットオフ
  data.put(0, 2).put(0, 2);                         // Cb、Crの差分は0
  data.put(0b1110, 4).put(0b0001, 4);               // Yの差分-8 → DC 8
  data.put(0, 1).put(1, 2).put(0, 1);               // 小さい符号1、そのあとブロックの終わり
  const OwnedRect r = dct_image(cmd, data);
  std::string why;
  CHECK(fb.apply(r.rect(0, 0, 160, 16, 1011), &why));
  CHECK(px(fb, 0, 0) == 0xFFFFFFFF && px(fb, 159, 7) == 0xFFFFFFFF);
  // DC 8 × 輝度の量子化値16 = 128 → (128 + 4) / 8 + 128 = 144。色差は128。
  CHECK(px(fb, 0, 8) == 0xFF909090 && px(fb, 7, 15) == 0xFF909090 && px(fb, 159, 15) == 0xFF909090);

  // 新しい表（type 2、0x0の矩形）。輝度の量子化値32でDCの刻みが2倍になる。
  ByteWriter q;
  q.u8(2);
  for (int i = 0; i < 128; ++i) q.u8(32);
  const OwnedRect tables = prefixed(q.take());
  CHECK(fb.apply(tables.rect(0, 0, 0, 0, 1011), &why));
  MsbBits cmd2, data2;
  cmd2.put(0, 1).put(5, 3).put(0, 1);
  data2.put(0, 3).put(0, 2).put(0, 2).put(0b1110, 4).put(0b0001, 4).put(0, 1).put(1, 2).put(0, 1);
  const OwnedRect r2 = dct_image(cmd2, data2);
  CHECK(fb.apply(r2.rect(8, 8, 8, 8, 1011), &why));
  CHECK(px(fb, 8, 8) == 0xFFA0A0A0);  // 8 × 32 = 256 → 160
  // 途中で切れたデータと未知のメッセージ種別は拒む。
  MsbBits short_data;
  short_data.put(0, 3);
  CHECK(!fb.apply(dct_image(cmd2, short_data).rect(8, 8, 8, 8, 1011), &why));
  const OwnedRect odd = prefixed({7, 0, 0});
  CHECK(!fb.apply(odd.rect(0, 0, 8, 8, 1011), &why));
}

TEST(fbu_length_and_framebuffer_parse) {
  // 1つの更新に、レイアウトのblob、1002の矩形、カーソルのSELECTを入れる。
  const Bytes chunk = stored_chunk({0x7F, 0xFF}, true);
  ByteWriter w;
  w.u8(0).u8(0).be16(3);
  w.be16(0).be16(0).be16(0).be16(0).be32(0x451).be16(4).be16(5).be16(1);
  w.be16(2).be16(3).be16(1).be16(1).be32(1002).be32(static_cast<uint32_t>(chunk.size())).bytes(chunk);
  w.be16(0).be16(0).be16(0).be16(0).be32(1104).be32(1000).be32(0);
  const Bytes msg = w.take();
  CHECK(session::fbu_length(msg.data(), msg.size()) == msg.size());
  for (size_t cut : {size_t(3), size_t(20), msg.size() - 1}) CHECK(session::fbu_length(msg.data(), cut) == 0);
  session::CursorCache cache;
  const session::FbuEvents ev = session::parse_fbu(msg, cache, true);
  CHECK(!ev.truncated && ev.pixels.size() == 1 && ev.cursors.size() == 1 && ev.layout.has_value());
  CHECK(ev.pixels[0].x == 2 && ev.pixels[0].y == 3 && ev.pixels[0].encoding == 1002 &&
        ev.pixels[0].size == 4 + chunk.size());
  // メディア経路では、1002はu16の長さつきblobで、ピクセルにはならない。
  CHECK(session::parse_fbu(msg, cache, false).pixels.empty());
  // 大きさのわからないエンコーディングは区切れない。
  const Bytes odd = ByteWriter().u8(0).u8(0).be16(1).be16(0).be16(0).be16(1).be16(1).be32(77).take();
  CHECK(session::fbu_length(odd.data(), odd.size()) == session::kUnknownLength);
}
