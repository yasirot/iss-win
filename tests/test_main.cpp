// 単体テスト。tools/gen_vectors.pyがvectors.incに書き出すベクタを使い、
// Python実装とバイト単位で一致することを確かめる。
#include <windows.h>
#include <bcrypt.h>

#include <cstdio>
#include <functional>
#include <string>
#include <vector>

#include "core/bytes.h"
#include "crypto/bigint.h"
#include "crypto/crypto.h"
#include "proto/enc1103.h"
#include <algorithm>
#include <tuple>

#include "app/connect_history.h"
#include "app/display_change.h"
#include "app/screen_layout.h"
#include "app/split_pictures.h"
#include "input/input_mapper.h"
#include "input/keyboard_grab.h"
#include "media/bitstream.h"
#include "media/hevc_refs.h"
#include "media/nalu.h"
#include "media/video_decoder.h"
#include "proto/rfb.h"
#include "util/bplist.h"
#include "util/zlib.h"
#include "vectors.inc"

using namespace iss;

namespace {

int g_failures = 0;
int g_checks = 0;
const char* g_current = "";

void check_impl(bool ok, const char* expr, const char* file, int line) {
  ++g_checks;
  if (!ok) {
    ++g_failures;
    std::fprintf(stderr, "  FAIL [%s] %s:%d: %s\n", g_current, file, line, expr);
  }
}

#define CHECK(expr) check_impl(static_cast<bool>(expr), #expr, __FILE__, __LINE__)
#define CHECK_HEX(actual, expected_hex)                                                         \
  do {                                                                                          \
    std::string a_ = to_hex(actual), e_ = (expected_hex);                                       \
    check_impl(a_ == e_, #actual " == " #expected_hex, __FILE__, __LINE__);                     \
    if (a_ != e_) std::fprintf(stderr, "    got:  %.120s\n    want: %.120s\n", a_.c_str(), e_.c_str()); \
  } while (0)

struct Test {
  const char* name;
  std::function<void()> fn;
};
std::vector<Test>& registry() {
  static std::vector<Test> r;
  return r;
}
struct Register {
  Register(const char* n, std::function<void()> f) { registry().push_back({n, std::move(f)}); }
};
#define TEST(name)                                  \
  static void name();                               \
  static Register reg_##name(#name, name);          \
  static void name()

Bytes H(const char* hex) { return from_hex(hex); }

// ── ハッシュ / KDF ─────────────────────────────────────────────────────────

TEST(sha_family) {
  Bytes in = H(kHashInput);
  CHECK_HEX(crypto::sha1(in), kSha1Abc);
  CHECK_HEX(crypto::sha256(in), kSha256Abc);
  CHECK_HEX(crypto::sha512(in), kSha512Abc);
}

TEST(pbkdf2_sha512) {
  Bytes pw = H(kPbkdf2Password);
  std::string pws(pw.begin(), pw.end());
  CHECK_HEX(crypto::pbkdf2_hmac_sha512(pws, H(kPbkdf2Salt), kPbkdf2Iters, 128), kPbkdf2Out);
  CHECK_HEX(crypto::pbkdf2_hmac_sha512("", H(kPbkdf2Salt), kPbkdf2Iters, 128), kPbkdf2EmptyOut);
}

TEST(random_bytes_differ) {
  Bytes a = crypto::random_bytes(32), b = crypto::random_bytes(32);
  CHECK(a.size() == 32);
  CHECK(a != b);
}

// ── AES ──────────────────────────────────────────────────────────────────

TEST(aes_ecb) {
  Bytes key = H(kAesKey), pt = H(kAesPlain);
  Bytes ct = crypto::aes_ecb_encrypt(key, pt);
  CHECK_HEX(ct, kAesEcbCipher);
  CHECK(crypto::aes_ecb_decrypt(key, ct) == pt);
}

TEST(aes_cbc_chains_across_calls) {
  Bytes key = H(kAesKey), iv = H(kAesIv), pt = H(kAesPlain);
  crypto::AesCbc enc(key, iv);
  Bytes ct = enc.encrypt(pt.data(), 32);
  Bytes ct2 = enc.encrypt(pt.data() + 32, 32);
  ct.insert(ct.end(), ct2.begin(), ct2.end());
  CHECK_HEX(ct, kAesCbcCipher);

  crypto::AesCbc dec(key, iv);
  Bytes back = dec.decrypt(ct.data(), 16);  // わざと半端な位置で分ける
  Bytes rest = dec.decrypt(ct.data() + 16, 48);
  back.insert(back.end(), rest.begin(), rest.end());
  CHECK(back == pt);
}

TEST(aes_rejects_partial_block) {
  bool threw = false;
  try { crypto::aes_ecb_encrypt(H(kAesKey), Bytes(15)); } catch (const crypto::CryptoError&) { threw = true; }
  CHECK(threw);
}

// ── 多倍長整数 ───────────────────────────────────────────────────────────────

TEST(bigint_roundtrip_and_arith) {
  using crypto::BigUint;
  BigUint x = BigUint::from_be(H(kBnX)), y = BigUint::from_be(H(kBnY)), m = BigUint::from_be(H(kBnMod));
  CHECK_HEX(x.to_be(512), kBnX);
  CHECK_HEX((x * y).to_be(887), kBnXY);
  CHECK_HEX(((x * y) % m).to_be(512), kBnXYMod);
  CHECK_HEX(crypto::mul_mod(x, y, m).to_be(512), kBnXYMod);
  CHECK_HEX((x + y).to_be(513), kBnXPlusY);
  CHECK_HEX((x - y).to_be(512), kBnXMinusY);
}

TEST(bigint_small_values) {
  using crypto::BigUint;
  CHECK(crypto::mod_exp(BigUint(4), BigUint(13), BigUint(497)) == BigUint(445));
  CHECK(crypto::mod_exp(BigUint(7), BigUint(0), BigUint(13)) == BigUint(1));
  CHECK((BigUint(5) - BigUint(5)).is_zero());
  CHECK(BigUint(0x1234).to_be(4) == H("00001234"));
  bool threw = false;
  try { BigUint(0x123456).to_be(2); } catch (const std::overflow_error&) { threw = true; }
  CHECK(threw);
}

TEST(bigint_modexp_4096) {
  using crypto::BigUint;
  BigUint r = crypto::mod_exp(BigUint::from_be(H(kBnBase)), BigUint::from_be(H(kBnExp)),
                              BigUint::from_be(H(kBnMod)));
  CHECK_HEX(r.to_be(512), kBnPow);
}

// ── RSA ──────────────────────────────────────────────────────────────────

// PKCS#1 v1.5は乱数を含むので、暗号文を比べるかわりに、対になる秘密鍵
// （Pythonが生成した素数から作る）で復号して確かめる。
Bytes rsa_decrypt_for_test(const Bytes& ct) {
  Bytes e = H(kRsaE), n = H(kRsaN), p = H(kRsaP), q = H(kRsaQ);
  BCRYPT_RSAKEY_BLOB hdr{};
  hdr.Magic = BCRYPT_RSAPRIVATE_MAGIC;
  hdr.BitLength = 2048;
  hdr.cbPublicExp = static_cast<ULONG>(e.size());
  hdr.cbModulus = static_cast<ULONG>(n.size());
  hdr.cbPrime1 = static_cast<ULONG>(p.size());
  hdr.cbPrime2 = static_cast<ULONG>(q.size());
  ByteWriter blob;
  blob.raw(&hdr, sizeof(hdr)).bytes(e).bytes(n).bytes(p).bytes(q);
  BCRYPT_KEY_HANDLE key = nullptr;
  if (!BCRYPT_SUCCESS(BCryptImportKeyPair(BCRYPT_RSA_ALG_HANDLE, nullptr, BCRYPT_RSAPRIVATE_BLOB, &key,
                                          const_cast<PUCHAR>(blob.data().data()),
                                          static_cast<ULONG>(blob.size()), 0))) {
    return {};
  }
  Bytes out(256);
  ULONG got = 0;
  NTSTATUS st = BCryptDecrypt(key, const_cast<PUCHAR>(ct.data()), static_cast<ULONG>(ct.size()), nullptr,
                              nullptr, 0, out.data(), static_cast<ULONG>(out.size()), &got, BCRYPT_PAD_PKCS1);
  BCryptDestroyKey(key);
  if (!BCRYPT_SUCCESS(st)) return {};
  out.resize(got);
  return out;
}

TEST(rsa_spki_and_pkcs1_import) {
  Bytes msg = H("00112233445566778899aabbccddeeff");
  for (const char* der : {kRsaSpkiDer, kRsaPkcs1Der}) {
    auto key = crypto::RsaPublicKey::from_der(H(der));
    CHECK(key.bits() == 2048);
    Bytes ct = key.encrypt_pkcs1v15(msg);
    CHECK(ct.size() == 256);
    CHECK(rsa_decrypt_for_test(ct) == msg);
  }
}

TEST(rsa_rejects_garbage) {
  bool threw = false;
  try { crypto::RsaPublicKey::from_der(H("3003020101")); } catch (const crypto::CryptoError&) { threw = true; }
  CHECK(threw);
}

// ── RFBメッセージの組み立て ─────────────────────────────────────────────────────────

TEST(rfb_builders_match_python) {
  CHECK_HEX(rfb::build_default_viewer_info_with_followup(), kViewerInfoWithFollowup);
  CHECK_HEX(rfb::build_virtual_display({.width = 1920, .height = 1080, .hidpi_scale = 2.0}), kVirtualDisplay1080p);
  CHECK_HEX(rfb::build_virtual_display({.width = 2560, .height = 1440, .hidpi_scale = 1.0, .hdr = true}),
            kVirtualDisplay1440Hdr);
  CHECK_HEX(rfb::build_virtual_display({.width = 1512, .height = 982, .hidpi_scale = 2.5}), kVirtualDisplayFrac);
  CHECK_HEX(rfb::build_set_encodings(), kSetEncodings);
  CHECK_HEX(rfb::build_post_encryption_toggle(), kPostEncryptionToggle);
  CHECK_HEX(rfb::build_key_event(true, 0xFF0D), kKeyEvent);
  CHECK_HEX(rfb::build_pointer_event(5, -3, 70000), kPointerEvent);
  CHECK_HEX(rfb::build_fbu_request(true, 0, 0, 1, 1), kFbuRequest);
}

TEST(display_layout_parse) {
  Bytes payload = H(kDisplayLayout);
  rfb::DisplayLayout layout;
  CHECK(rfb::parse_apple_display_layout(payload.data(), payload.size(), layout));
  CHECK(layout.backing_w == kDisplayLayoutBackingW);
  CHECK(layout.backing_h == kDisplayLayoutBackingH);
  CHECK(layout.rects.size() == std::size(kDisplayLayoutRects));
  for (size_t i = 0; i < layout.rects.size() && i < std::size(kDisplayLayoutRects); ++i) {
    const auto& r = layout.rects[i];
    const auto& e = kDisplayLayoutRects[i];
    CHECK(r.display_id == e.id && r.x == e.x && r.y == e.y && r.w == e.w && r.h == e.h);
  }
  CHECK(!rfb::parse_apple_display_layout(payload.data(), 10, layout));
}

// ── enc1103 ──────────────────────────────────────────────────────────────

TEST(enc1103_unwraps_key) {
  proto::StreamCipher c(H(kEncBlob), H(kEncEcbKey));
  CHECK_HEX(c.cbc_key(), kEncCbcKey);
}

TEST(enc1103_encrypt_matches_python) {
  proto::StreamCipher c(H(kEncBlob), H(kEncEcbKey));
  for (int i = 0; i < kEncMessageCount; ++i) {
    CHECK_HEX(c.encrypt_message(H(kEncMessages[i])), kEncRecords[i]);
  }
}

TEST(enc1103_decrypt_python_stream) {
  Bytes stream;
  for (int i = 0; i < kEncMessageCount; ++i) {
    Bytes r = H(kEncRecords[i]);
    stream.insert(stream.end(), r.begin(), r.end());
  }
  proto::StreamCipher c(H(kEncBlob), H(kEncEcbKey));
  size_t consumed = 0;
  auto msgs = c.decrypt_stream(stream, &consumed);
  CHECK(consumed == stream.size());
  CHECK(static_cast<int>(msgs.size()) == kEncMessageCount);
  for (int i = 0; i < kEncMessageCount && i < static_cast<int>(msgs.size()); ++i) {
    CHECK_HEX(msgs[i], kEncMessages[i]);
  }
}

TEST(enc1103_stream_keeps_partial_tail) {
  Bytes first = H(kEncRecords[0]), second = H(kEncRecords[1]);
  Bytes buf = first;
  buf.insert(buf.end(), second.begin(), second.begin() + 5);  // 途中で切れたレコード
  proto::StreamCipher c(H(kEncBlob), H(kEncEcbKey));
  size_t consumed = 0;
  auto msgs = c.decrypt_stream(buf, &consumed);
  CHECK(msgs.size() == 1);
  CHECK(consumed == first.size());
  // 残りをあとから渡しても、CBCの連鎖は正しく続く。
  Bytes rest(second.begin(), second.end());
  auto more = c.decrypt_stream(rest, &consumed);
  CHECK(more.size() == 1 && more[0].empty());
}

TEST(enc1103_tampered_record_is_dropped) {
  Bytes rec = H(kEncRecords[2]);
  rec.back() ^= 1;
  proto::StreamCipher c(H(kEncBlob), H(kEncEcbKey));
  auto msgs = c.decrypt_stream(rec);
  CHECK(msgs.empty());
}

TEST(enc1103_roundtrip_own_output) {
  proto::StreamCipher tx(H(kEncBlob), H(kEncEcbKey)), rx(H(kEncBlob), H(kEncEcbKey));
  Bytes stream;
  std::vector<Bytes> sent;
  for (size_t n : {0u, 1u, 15u, 16u, 17u, 1000u}) {
    Bytes m = crypto::random_bytes(n);
    Bytes r = tx.encrypt_message(m);
    stream.insert(stream.end(), r.begin(), r.end());
    sent.push_back(m);
  }
  auto got = rx.decrypt_stream(stream);
  CHECK(got == sent);
}

// ── zlib ─────────────────────────────────────────────────────────────────

TEST(zlib_inflates_python_output) {
  Bytes plain = H(kZlibPlain);
  for (const char* z : {kZlibLevel6, kZlibLevel9, kZlibLevel1}) {
    auto out = zlib::decompress(H(z));
    CHECK(out.has_value() && *out == plain);
  }
  auto empty = zlib::decompress(H(kZlibEmpty));
  CHECK(empty.has_value() && empty->empty());
}

TEST(zlib_stored_roundtrip) {
  for (size_t n : {0u, 1u, 300u, 65535u, 65536u, 200000u}) {
    Bytes data = crypto::random_bytes(n);
    auto back = zlib::decompress(zlib::compress_stored(data));
    CHECK(back.has_value() && *back == data);
  }
}

TEST(zlib_rejects_corruption) {
  Bytes z = H(kZlibLevel6);
  Bytes bad_sum = z;
  bad_sum.back() ^= 1;
  CHECK(!zlib::decompress(bad_sum));
  Bytes truncated(z.begin(), z.begin() + z.size() / 2);
  CHECK(!zlib::decompress(truncated));
  CHECK(!zlib::decompress(H(kZlibLevel6), 100));  // 出力の上限
}

// ── バイナリplist ─────────────────────────────────────────────────────────

TEST(bplist_writer_matches_plistlib) {
  Bytes expected = H(kPlistGeneric);
  auto parsed = plist::parse_binary(expected);
  CHECK(parsed.has_value());
  if (!parsed) return;
  // 読んだ内容を書き戻す。バイト列が一致すれば、writerはplistlibと同じ
  // オブジェクトの順序、重複の除き方、サイズの区分に従っている。
  CHECK_HEX(plist::write_binary(*parsed), kPlistGeneric);
  const plist::Value* v = parsed->get("big");
  CHECK(v && v->type == plist::Value::Type::Int && v->i == 70000);
  v = parsed->get("huge");
  CHECK(v && v->i == (1ll << 40));
  v = parsed->get("jp");
  CHECK(v && v->s == "日本語");
  v = parsed->get("zeta");
  CHECK(v && v->data == H("000102"));
}

TEST(bplist_rejects_garbage) {
  Bytes good = H(kPlistGeneric);
  CHECK(!plist::parse_binary(Bytes(good.begin(), good.end() - 1)));
  Bytes bad = good;
  bad[bad.size() - 1] = 0xFF;  // オフセット表を指す位置が範囲外
  CHECK(!plist::parse_binary(bad));
  CHECK(!plist::parse_binary(H("00112233")));
}

// ── ビットストリーム ────────────────────────────────────────────────────────────

TEST(emulation_prevention_removal) {
  CHECK(media::remove_emulation_prevention(H("0000030100000302")) == H("000001000002"));
  CHECK(media::remove_emulation_prevention(H("000003")) == H("0000"));
  CHECK(media::remove_emulation_prevention(H("0000")) == H("0000"));
  CHECK(media::remove_emulation_prevention(H("00000300000301")) == H("0000000001"));
}

TEST(exp_golomb) {
  // 1 | 010 | 011 | 00100 | 00101 → ue 0,1,2,3,4
  Bytes b = {0b10100110, 0b01000010, 0b10000000};
  media::BitReader br(b);
  CHECK(br.read_ue() == 0);
  CHECK(br.read_ue() == 1);
  CHECK(br.read_ue() == 2);
  CHECK(br.read_ue() == 3);
  CHECK(br.read_ue() == 4);
  // se: codeNum 1 → +1, 2 → -1, 3 → +2
  Bytes s = {0b01001100, 0b10000000};  // 010 011 00100
  media::BitReader bs(s);
  CHECK(bs.read_se() == 1);
  CHECK(bs.read_se() == -1);
  CHECK(bs.read_se() == 2);
  Bytes zeros(16, 0);
  media::BitReader bz(zeros);
  CHECK(bz.read_ue() == (uint64_t(1) << 32) - 1);  // 先頭の0は32個で打ち切り、末尾の先は0と読む
}

// ── 映像デコーダ ────────────────────────────────────────────────────────

Bytes read_file(const std::string& path) {
  Bytes out;
  FILE* f = nullptr;
  if (fopen_s(&f, path.c_str(), "rb") || !f) return out;
  uint8_t buf[65536];
  size_t n;
  while ((n = fread(buf, 1, sizeof(buf), f)) > 0) out.insert(out.end(), buf, buf + n);
  fclose(f);
  return out;
}

std::vector<std::string> read_framemd5(const std::string& path) {
  std::vector<std::string> out;
  FILE* f = nullptr;
  if (fopen_s(&f, path.c_str(), "rb") || !f) return out;
  char line[512];
  while (fgets(line, sizeof(line), f)) {
    if (line[0] == '#') continue;
    std::string s(line);
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r' || s.back() == ' ')) s.pop_back();
    size_t comma = s.rfind(',');
    if (comma != std::string::npos) out.push_back(s.substr(s.find_first_not_of(' ', comma + 1)));
  }
  fclose(f);
  return out;
}

std::string md5_hex(const Bytes& b) {
  Bytes out(16);
  BCryptHash(BCRYPT_MD5_ALG_HANDLE, nullptr, 0, const_cast<PUCHAR>(b.data()), static_cast<ULONG>(b.size()),
             out.data(), 16);
  return to_hex(out);
}

// framemd5がハッシュを取るときと同じく、行のパディングを除いてプレーンを詰める
// （ハードウェアの出力をyuv420pと比べられるよう、NV12はplanarに分ける）。
Bytes pack_planes(const media::VideoFrame& f) {
  Bytes out;
  auto rows = [&](const uint8_t* p, int stride, int w, int h) {
    for (int y = 0; y < h; ++y) out.insert(out.end(), p + size_t(y) * stride, p + size_t(y) * stride + w);
  };
  rows(f.plane(0), f.stride(0), f.width, f.height);
  if (f.layout == media::VideoFrame::Layout::Planar) {
    rows(f.plane(1), f.stride(1), f.chroma_width, f.chroma_height);
    rows(f.plane(2), f.stride(2), f.chroma_width, f.chroma_height);
  } else {
    for (int plane = 0; plane < 2; ++plane) {
      for (int y = 0; y < f.chroma_height; ++y) {
        const uint8_t* row = f.plane(1) + size_t(y) * f.stride(1);
        for (int x = 0; x < f.chroma_width; ++x) out.push_back(row[2 * x + plane]);
      }
    }
  }
  return out;
}

TEST(hevc_sps_gives_the_picture_size_and_chroma_format) {
  for (auto [name, chroma] : {std::pair{"hevc444", 3}, std::pair{"hevc420", 1}}) {
    const Bytes stream = read_file(std::string(ISS_TEST_DATA_DIR) + "/" + name + ".h265");
    std::optional<media::HevcSpsInfo> sps;
    for (const Bytes& nal : media::split_annexb(stream)) {
      if (!sps && !nal.empty()) sps = media::parse_hevc_sps(nal);
    }
    CHECK(sps.has_value());
    if (!sps) continue;
    CHECK(sps->width == 640 && sps->height == 360);
    CHECK(sps->chroma_format_idc == chroma);
    CHECK(sps->level_idc > 0);
  }
  CHECK(!media::parse_hevc_sps(Bytes{0x40, 0x01, 0x0c, 0x01}));  // VPS
}

// テスト用のクリップは10ピクチャごとにIDRで、あいだはPピクチャ。全部届けば
// どのピクチャもcleanになる。1枚抜くと、次のIDRまでの残りが
// おかしくなる。
std::vector<bool> hevc_clean_flags(int leave_out) {
  media::HevcRefTracker refs;
  std::vector<bool> clean;
  for (const Bytes& nal : media::split_annexb(read_file(std::string(ISS_TEST_DATA_DIR) + "/hevc420.h265"))) {
    if (nal.size() < 3) continue;
    const int t = media::hevc_nal_type(nal[0]);
    if (t == media::HEVC_NAL_SPS) CHECK(refs.set_sps(nal));
    if (t == media::HEVC_NAL_PPS) CHECK(refs.set_pps(nal));
    if (t > 31 || !(nal[2] & 0x80)) continue;
    if (static_cast<int>(clean.size()) == leave_out) {
      clean.push_back(false);
      continue;
    }
    const auto pic = refs.add(nal);
    CHECK(pic.has_value());
    clean.push_back(pic && pic->clean);
  }
  return clean;
}

// キーフレームの最初のパケットは、丸ごとでもFU-Aの先頭でも、キーフレーム要求への
// 答えの目印になる。Pスライスの最初のパケットはならない。
TEST(avc_payload_starts_keyframe_whole_and_fragmented) {
  std::vector<Bytes> slices;
  for (const Bytes& nal : media::split_annexb(read_file(std::string(ISS_TEST_DATA_DIR) + "/h264.h264"))) {
    const int t = nal.empty() ? 0 : media::avc_nal_type(nal[0]);
    if (t == media::AVC_NAL_SLICE_IDR || t == media::AVC_NAL_SLICE_NONIDR) slices.push_back(nal);
  }
  CHECK(slices.size() >= 2);
  if (slices.size() < 2) return;
  auto fu_start = [](const Bytes& nal) {
    Bytes p = {static_cast<uint8_t>((nal[0] & 0xE0) | media::AVC_NAL_FU_A), static_cast<uint8_t>(0x80 | (nal[0] & 0x1F))};
    p.insert(p.end(), nal.begin() + 1, nal.begin() + static_cast<std::ptrdiff_t>(std::min<size_t>(nal.size(), 40)));
    return p;
  };
  CHECK(media::avc_payload_starts_keyframe(slices[0]));
  CHECK(media::avc_payload_starts_keyframe(fu_start(slices[0])));
  CHECK(!media::avc_payload_starts_keyframe(slices[1]));
  CHECK(!media::avc_payload_starts_keyframe(fu_start(slices[1])));
}

TEST(hevc_ref_tracker_follows_a_lost_picture) {
  const std::vector<bool> all = hevc_clean_flags(-1);
  CHECK(all.size() == 30);
  CHECK(std::all_of(all.begin(), all.end(), [](bool c) { return c; }));
  const std::vector<bool> lost = hevc_clean_flags(13);
  CHECK(lost.size() == 30);
  for (int i = 0; i < static_cast<int>(lost.size()); ++i) CHECK(lost[i] == (i < 13 || i >= 20));
}

struct DecodeRun {
  std::vector<std::string> md5s;
  std::vector<int> tiles;
  std::vector<int> expected_tiles;
  std::string backend;
  bool any_error = false;
};

DecodeRun decode_clip(const char* name, media::Codec codec, bool hw) {
  DecodeRun run;
  std::string base = std::string(ISS_TEST_DATA_DIR) + "/" + name;
  Bytes stream = read_file(base + (codec == media::Codec::Hevc ? ".h265" : ".h264"));
  if (stream.empty()) return run;

  // パラメータセット → Annex-Bのextradata。それ以外はNALUごとに渡し、pts→タイルの
  // 振り分けを試すため、タイル番号を交互に変える。
  Bytes extradata;
  std::vector<Bytes> feed;
  bool have_param[64] = {};
  for (Bytes& nal : media::split_annexb(stream)) {
    if (nal.empty()) continue;
    int t = codec == media::Codec::Hevc ? media::hevc_nal_type(nal[0]) : media::avc_nal_type(nal[0]);
    bool is_param = codec == media::Codec::Hevc ? (t >= 32 && t <= 34) : (t == 7 || t == 8);
    if (is_param) {
      if (!have_param[t]) {
        have_param[t] = true;
        extradata.insert(extradata.end(), {0, 0, 0, 1});
        extradata.insert(extradata.end(), nal.begin(), nal.end());
      }
      continue;
    }
    feed.push_back(std::move(nal));
  }

  media::VideoDecoder dec;
  dec.open({codec, hw, -1}, extradata);
  std::vector<media::VideoFrame> frames;
  int slice_index = 0;
  for (const Bytes& nal : feed) {
    int tile = slice_index % 2;
    size_t before = frames.size();
    dec.decode(nal, tile, frames);
    bool is_slice = codec == media::Codec::Hevc ? media::hevc_nal_type(nal[0]) <= 31
                                                : (media::avc_nal_type(nal[0]) >= 1 && media::avc_nal_type(nal[0]) <= 5);
    if (is_slice) {
      run.expected_tiles.push_back(tile);
      ++slice_index;
    }
    (void)before;
  }
  dec.flush(frames);
  for (const auto& f : frames) {
    run.md5s.push_back(md5_hex(pack_planes(f)));
    run.tiles.push_back(f.tile);
    run.any_error |= f.had_error;
  }
  run.backend = dec.backend();
  return run;
}

void check_clip(const char* name, media::Codec codec, bool hw) {
  auto ref = read_framemd5(std::string(ISS_TEST_DATA_DIR) + "/" + name + ".md5");
  CHECK(ref.size() == 30);
  DecodeRun run = decode_clip(name, codec, hw);
  std::printf("    %s %s: %zu frames, backend=%s\n", name, hw ? "hw-preferred" : "software", run.md5s.size(),
              run.backend.c_str());
  CHECK(run.md5s.size() == ref.size());
  size_t mismatches = 0;
  for (size_t i = 0; i < run.md5s.size() && i < ref.size(); ++i) mismatches += run.md5s[i] != ref[i];
  CHECK(mismatches == 0);
  if (mismatches) std::printf("    %zu/%zu frames differ from the reference\n", mismatches, run.md5s.size());
  CHECK(!run.any_error);
  // どのフレームも、元になったNALUのタイルに戻る。
  CHECK(run.tiles.size() <= run.expected_tiles.size());
  bool routed = true;
  for (size_t i = 0; i < run.tiles.size() && i < run.expected_tiles.size(); ++i) routed &= run.tiles[i] == run.expected_tiles[i];
  CHECK(routed);
}

TEST(decode_hevc444_software) { check_clip("hevc444", media::Codec::Hevc, false); }
TEST(decode_hevc420_software) { check_clip("hevc420", media::Codec::Hevc, false); }
TEST(decode_h264_software) { check_clip("h264", media::Codec::H264, false); }
TEST(decode_hevc444_hw_preferred) { check_clip("hevc444", media::Codec::Hevc, true); }
TEST(decode_hevc420_hw_preferred) { check_clip("hevc420", media::Codec::Hevc, true); }
TEST(decode_h264_hw_preferred) { check_clip("h264", media::Codec::H264, true); }

// ── 入力の変換 ────────────────────────────────────────────────────────

struct Recorded {
  std::vector<std::pair<bool, uint32_t>> keys;
  std::vector<std::tuple<uint8_t, int, int>> ptr;
  input::Sink sink() {
    return {[this](bool d, uint32_t k) { keys.emplace_back(d, k); },
            [this](uint8_t b, int x, int y) { ptr.emplace_back(b, x, y); }};
  }
};

constexpr intptr_t kExt = intptr_t(1) << 24;

TEST(input_special_keys) {
  CHECK(input::vk_to_keysym(VK_RETURN, false, 0x1c) == 0xff0d);
  CHECK(input::vk_to_keysym(VK_SHIFT, false, 0x2a) == 0xffe1);  // 左Shift
  CHECK(input::vk_to_keysym(VK_SHIFT, false, 0x36) == 0xffe2);  // 右Shift
  CHECK(input::vk_to_keysym(VK_CONTROL, true, 0x1d) == 0xffe4);
  CHECK(input::vk_to_keysym(VK_F12, false, 0x58) == 0xffc9);
  CHECK(input::vk_to_keysym(VK_SPACE, false, 0x39) == 0);  // WM_CHARで送る
  CHECK(input::vk_to_keysym('A', false, 0x1e) == 0);
}

TEST(input_ctrl_letter_is_synthesised) {
  Recorded r;
  input::InputMapper m(r.sink());
  m.key_down(VK_CONTROL, 0);
  m.key_down('C', 0);
  m.char_input(0x03);  // Ctrl+Cの制御コードは無視する
  m.key_up('C', 0);
  m.key_up(VK_CONTROL, 0);
  std::vector<std::pair<bool, uint32_t>> want = {{true, 0xffe3}, {true, 'c'}, {false, 'c'}, {false, 0xffe3}};
  CHECK(r.keys == want);
}

TEST(input_chars_use_layout_and_unicode) {
  Recorded r;
  input::InputMapper m(r.sink());
  m.key_down('A', 0);  // 修飾キーなしでは、キー自体は何も送らない
  m.char_input(L'A');
  m.char_input(L'あ');                  // あ
  m.char_input(0xD83D);                     // U+1F600をサロゲートペアで
  m.char_input(0xDE00);
  m.char_input(L'\r');                      // 制御文字はWM_KEYDOWNの側から送る
  std::vector<std::pair<bool, uint32_t>> want = {
      {true, 'A'}, {false, 'A'}, {true, 0x3042}, {false, 0x3042}, {true, 0x1F600}, {false, 0x1F600}};
  CHECK(r.keys == want);
}

TEST(input_altgr_chars_not_duplicated) {
  Recorded r;
  input::InputMapper m(r.sink());
  m.key_down(VK_CONTROL, 0);     // AltGr = LCtrl + RAlt
  m.key_down(VK_MENU, kExt);
  m.key_down('Q', 0);            // ドイツ語配列のAltGr+Qは@で、WM_CHARで届く
  m.char_input(L'@');
  size_t letters = std::count_if(r.keys.begin(), r.keys.end(), [](auto& k) { return k.second == 'q'; });
  CHECK(letters == 0);
  CHECK(std::count(r.keys.begin(), r.keys.end(), std::pair<bool, uint32_t>{true, '@'}) == 1);
}

TEST(input_ctrl_as_cmd) {
  Recorded r;
  input::InputMapper m(r.sink(), {.ctrl_as_cmd = true});
  m.key_down(VK_CONTROL, 0);
  m.key_up(VK_CONTROL, 0);
  m.key_down(VK_CONTROL, kExt);
  std::vector<std::pair<bool, uint32_t>> want = {{true, 0xffeb}, {false, 0xffeb}, {true, 0xffeb}};
  CHECK(r.keys == want);
}

TEST(input_alt_is_option_and_win_is_cmd_on_both_sides) {
  Recorded r;
  input::InputMapper m(r.sink());
  m.key_down(VK_MENU, 0);       // 左Alt
  m.key_down('E', 0);
  m.key_up('E', 0);
  m.key_up(VK_MENU, 0);
  m.key_down(VK_MENU, kExt);    // 右Alt（AltGrでない配列）
  m.key_up(VK_MENU, kExt);
  m.key_down(VK_RWIN, kExt);
  m.key_up(VK_RWIN, kExt);
  std::vector<std::pair<bool, uint32_t>> want = {{true, 0xffe7}, {true, 'e'},    {false, 'e'},  {false, 0xffe7},
                                                 {true, 0xffe7}, {false, 0xffe7}, {true, 0xffeb}, {false, 0xffeb}};
  CHECK(r.keys == want);
}

TEST(input_altgr_is_not_sent_as_option) {
  Recorded r;
  input::InputMapper m(r.sink());
  m.key_down(VK_CONTROL, 0);
  m.key_down(VK_MENU, kExt);
  m.key_up(VK_MENU, kExt);
  m.key_up(VK_CONTROL, 0);
  CHECK(std::none_of(r.keys.begin(), r.keys.end(), [](auto& k) { return k.second == 0xffe7; }));
}

using KeyLog = std::vector<std::pair<bool, uint32_t>>;

TEST(input_shortcut_punctuation_and_numpad) {
  Recorded r;
  input::InputMapper m(r.sink());
  m.key_down(VK_LWIN, kExt);       // Cmd+,（設定）
  m.key_down(VK_OEM_COMMA, 0);
  m.char_input(L',');              // 二重には送らない
  m.key_up(VK_OEM_COMMA, 0);
  m.key_down(VK_NUMPAD5, 0);
  m.key_up(VK_NUMPAD5, 0);
  m.key_up(VK_LWIN, kExt);
  KeyLog want = {{true, 0xffeb}, {true, ','}, {false, ','}, {true, '5'}, {false, '5'}, {false, 0xffeb}};
  CHECK(r.keys == want);
  CHECK(input::shortcut_keysym(VK_OEM_PERIOD) == '.');
  CHECK(input::shortcut_keysym(VK_RETURN) == 0);
}

TEST(input_key_released_after_its_modifier) {
  Recorded r;
  input::InputMapper m(r.sink());
  m.key_down(VK_CONTROL, 0);
  m.key_down('Z', 0);
  m.key_up(VK_CONTROL, 0);  // Ctrlを先に離しても、"z"のキーアップは必ず送る
  m.key_up('Z', 0);
  KeyLog want = {{true, 0xffe3}, {true, 'z'}, {false, 0xffe3}, {false, 'z'}};
  CHECK(r.keys == want);
}

TEST(input_modifier_repeat_sent_once) {
  Recorded r;
  input::InputMapper m(r.sink());
  for (int i = 0; i < 3; ++i) m.key_down(VK_SHIFT, 0x2a << 16);
  m.key_down(VK_LEFT, kExt);  // ほかのキーはオートリピートをそのまま送る
  m.key_down(VK_LEFT, kExt);
  m.key_up(VK_SHIFT, 0x2a << 16);
  KeyLog want = {{true, 0xffe1}, {true, 0xff51}, {true, 0xff51}, {false, 0xffe1}};
  CHECK(r.keys == want);
}

TEST(input_hook_and_window_vks_are_one_key) {
  Recorded r;
  input::InputMapper m(r.sink());
  m.key_down(VK_SHIFT, 0x36 << 16);     // WM_KEYDOWNからの右Shift
  m.key_down(VK_LWIN, 0x5b << 16 | kExt);  // フックからは左右つきのコード
  m.key_down('4', 0x05 << 16);
  m.key_up('4', 0x05 << 16);
  m.key_up(VK_LWIN, 0x5b << 16 | kExt);
  m.key_up(VK_RSHIFT, 0x36 << 16);      // フック経由で離す
  KeyLog want = {{true, 0xffe2}, {true, 0xffeb}, {true, '4'}, {false, '4'}, {false, 0xffeb}, {false, 0xffe2}};
  CHECK(r.keys == want);
}

TEST(grab_takes_win_and_keys_held_with_it) {
  input::GrabFilter f;
  DWORD t = 1000;
  CHECK(!f.take('A', true, true, t));          // ふつうの入力はWindowsに任せる
  CHECK(!f.take('A', false, true, ++t));
  CHECK(f.take(VK_LWIN, true, true, ++t));     // Winはシェルに渡さない
  CHECK(f.take(VK_LWIN, true, true, t += 30));  // そのオートリピート
  CHECK(f.take(VK_LSHIFT, true, true, ++t));   // Winと一緒に押したキー
  CHECK(f.take('C', true, true, ++t));
  CHECK(f.take(VK_LWIN, false, true, ++t));
  CHECK(f.take('C', false, true, ++t));        // Winより後に離しても、こちらで取る
  CHECK(f.take(VK_LSHIFT, false, true, ++t));
  CHECK(!f.take('C', true, true, ++t));        // Winはもう離れている
  CHECK(!f.take('C', false, true, ++t));
}

TEST(grab_leaves_keys_alone_when_inactive_or_pressed_before) {
  input::GrabFilter f;
  DWORD t = 1000;
  CHECK(!f.take(VK_LWIN, true, false, t));     // キーボードはほかのウィンドウにある
  CHECK(!f.take('E', true, true, ++t));
  CHECK(!f.take(VK_LWIN, false, true, ++t));   // 離しは押したときの扱いに従う
  CHECK(!f.take('E', false, true, ++t));
  CHECK(!f.take(VK_LCONTROL, true, true, ++t));  // Winより先に押していたキーはWindowsに残す
  CHECK(f.take(VK_LWIN, true, true, ++t));
  CHECK(!f.take(VK_LCONTROL, true, true, t += 30));
  CHECK(!f.take(VK_LCONTROL, false, true, ++t));
  CHECK(f.take(VK_LWIN, false, true, ++t));
}

TEST(grab_takes_space_held_with_alt) {
  input::GrabFilter f;
  DWORD t = 1000;
  CHECK(!f.take(VK_LMENU, true, true, t));       // Alt自体はWindowsに渡す
  CHECK(f.take(VK_SPACE, true, true, ++t));      // ランチャーに取られないように横取りする
  CHECK(!f.take(VK_LMENU, false, true, ++t));
  CHECK(f.take(VK_SPACE, false, true, ++t));     // Altより後に離しても、こちらで取る
  CHECK(!f.take(VK_SPACE, true, true, ++t));     // Altなしのスペースはそのまま
  CHECK(!f.take(VK_SPACE, false, true, ++t));
  CHECK(!f.take(VK_RMENU, true, false, ++t));    // キーボードはほかのウィンドウにある
  CHECK(!f.take(VK_SPACE, true, false, ++t));
  CHECK(!f.take(VK_SPACE, false, false, ++t));
  CHECK(!f.take(VK_RMENU, false, false, ++t));
  CHECK(!f.take(VK_LMENU, true, true, ++t));
  CHECK(!f.take(VK_TAB, true, true, ++t));       // Alt+Tabには手を付けない
}

TEST(grab_recovers_from_lost_releases) {
  input::GrabFilter f;
  DWORD t = 1000;
  CHECK(f.take(VK_LWIN, true, true, t));
  CHECK(f.take('L', true, true, ++t));  // Win+Lでは、ロック画面が両方のキーアップを受け取ってしまう
  t += 60000;
  CHECK(!f.take('L', true, false, t));  // ずっと後にほかの場所で打ったキーは横取りしない
  CHECK(!f.take('L', false, false, ++t));
  f.reset();                            // ロック解除
  CHECK(!f.take('A', true, true, ++t));
}

TEST(input_release_all_on_focus_loss) {
  Recorded r;
  input::InputMapper m(r.sink());
  m.key_down(VK_SHIFT, 0x2a << 16);
  m.key_down(VK_LEFT, kExt);
  m.move(10, 20);
  m.button(0, true);
  r.keys.clear();
  r.ptr.clear();
  m.release_all();
  CHECK(r.keys.size() == 2 && !r.keys[0].first && !r.keys[1].first);
  CHECK(r.ptr.size() == 1 && std::get<0>(r.ptr[0]) == 0);
}

TEST(input_buttons_use_apple_mask) {
  Recorded r;
  input::InputMapper m(r.sink());
  m.move(5, 6);
  m.button(1, true);  // 右ボタン → bit 1
  m.button(2, true);  // 中ボタン → bit 2
  m.button(1, false);
  CHECK(std::get<0>(r.ptr[1]) == 0x02);
  CHECK(std::get<0>(r.ptr[2]) == 0x06);
  CHECK(std::get<0>(r.ptr[3]) == 0x04);
}

TEST(input_wheel_ticks_and_accel) {
  Recorded r;
  input::InputMapper m(r.sink());
  m.move(1, 2);
  r.ptr.clear();
  m.wheel(1.0, 10000);  // ゆっくり1ノッチ上へ。bit 3を12ティック
  CHECK(r.ptr.size() == 24);
  CHECK(std::get<0>(r.ptr[0]) == 0x08 && std::get<0>(r.ptr[1]) == 0);
  r.ptr.clear();
  m.wheel(-1.0, 10010);  // 10 ms後は×10に加速して下へ。1イベントあたり50で打ち切る
  CHECK(r.ptr.size() == 100);
  CHECK(std::get<0>(r.ptr[0]) == 0x10);
  r.ptr.clear();
  m.wheel(0.05, 20000);  // 1ティックに満たないが、繰り越した70ティックがまだ残っている
  CHECK(!r.ptr.empty());
}

// ── 全画面 ──────────────────────────────────────────────────────────

TEST(fullscreen_each_window_keeps_its_monitor) {
  CHECK(app::fullscreen_monitors({1, 0}, {false, false}) == std::vector<int>({1, 0}));
  CHECK(app::fullscreen_monitors({0}, {false, false, false}) == std::vector<int>({0}));
}

TEST(fullscreen_window_sharing_a_monitor_moves_to_a_free_one) {
  // 両方のウィンドウがモニタ1にある。全画面を頼んだほうが残り、もう一方はモニタ0を使う。
  CHECK(app::fullscreen_monitors({1, 1}, {false, false}) == std::vector<int>({1, 0}));
  // モニタ0にはもう全画面のウィンドウがある。
  CHECK(app::fullscreen_monitors({0}, {true, false}) == std::vector<int>({1}));
  // どのモニタにも乗っていない（不明）ときは、最初の空いたモニタ。
  CHECK(app::fullscreen_monitors({-1, 5}, {false, false}) == std::vector<int>({0, 1}));
}

TEST(fullscreen_monitors_follow_the_macs_display_order) {
  // ウィンドウ1が右のモニタ、ウィンドウ2が左にある。Mac側ではディスプレイ2が右にある。
  CHECK(app::monitors_against_mac_order(3840, 0, 0, 1920));
  CHECK(!app::monitors_against_mac_order(0, 3840, 0, 1920));
  CHECK(app::monitors_against_mac_order(0, 3840, 1920, 0));  // ディスプレイ2が左
  CHECK(!app::monitors_against_mac_order(0, 0, 0, 1920));    // 同じモニタ
  CHECK(!app::monitors_against_mac_order(0, 3840, 0, 0));    // Mac側で上下に並ぶ
}

// ── 接続ダイアログのMac一覧 ─────────────────────────────────────

app::HostEntry host_entry(const wchar_t* host, int port, const wchar_t* user) {
  app::HostEntry e;
  e.host = host;
  e.port = port;
  e.user = user;
  return e;
}

TEST(connect_history_parses_saved_password_targets) {
  const auto a = app::parse_credential_target(L"iShareScreen/iss-win:me@macBox:5900");
  CHECK(a && a->user == L"me" && a->host == L"macBox" && a->port == 5900 && !a->has_options);
  const auto v6 = app::parse_credential_target(L"iShareScreen/iss-win:me@fd00:db8:1::e3c:5901");
  CHECK(v6 && v6->host == L"fd00:db8:1::e3c" && v6->port == 5901);
  CHECK(!app::parse_credential_target(L"Other/app:me@host:5900"));
  CHECK(!app::parse_credential_target(L"iShareScreen/iss-win:me@host"));
  CHECK(!app::parse_credential_target(L"iShareScreen/iss-win:@host:5900"));
  CHECK(!app::parse_credential_target(L"iShareScreen/iss-win:me@:5900"));
  CHECK(!app::parse_credential_target(L"iShareScreen/iss-win:me@host:99999"));
}

TEST(connect_history_newest_first_without_duplicates) {
  std::vector<app::HostEntry> list = {host_entry(L"macBox", 5900, L"me"), host_entry(L"mini", 5900, L"me")};
  app::remember_entry(list, host_entry(L"MINI", 5900, L"me"));  // ホスト名は大文字小文字を区別しない
  CHECK(list.size() == 2 && list[0].host == L"MINI" && list[1].host == L"macBox");
  app::remember_entry(list, host_entry(L"mini", 5901, L"me"));  // ポートが違えば別の項目
  CHECK(list.size() == 3);
  for (int i = 0; i < 20; ++i) app::remember_entry(list, host_entry(L"h", 6000 + i, L"u"), 10);
  CHECK(list.size() == 10 && list[0].port == 6019);
}

TEST(connect_history_merges_saved_passwords_at_the_end) {
  std::vector<app::HostEntry> list = {host_entry(L"macBox", 5900, L"me")};
  app::merge_entries(list, {host_entry(L"macbox", 5900, L"me"), host_entry(L"100.64.0.1", 5900, L"me")});
  CHECK(list.size() == 2 && list[1].host == L"100.64.0.1");
}

TEST(connect_history_labels) {
  CHECK(app::entry_label(host_entry(L"macBox", 5900, L"me")) == L"me@macBox");
  CHECK(app::entry_label(host_entry(L"mini", 5901, L"me")) == L"me@mini:5901");
  CHECK(app::entry_label(host_entry(L"fd00::1", 5901, L"me")) == L"me@[fd00::1]:5901");
}

TEST(fullscreen_window_without_a_free_monitor_stays) {
  CHECK(app::fullscreen_monitors({0, 0}, {false}) == std::vector<int>({0, -1}));
  CHECK(app::fullscreen_monitors({0}, {true}) == std::vector<int>({-1}));
  CHECK(app::fullscreen_monitors({0}, {}) == std::vector<int>({-1}));
}

TEST(display_change_ends_with_a_picture_of_the_answered_size) {
  using C = app::DisplayChange::Clock;
  const C::time_point t0{};
  app::DisplayChange c;
  c.on_layout(t0, 1, 3840, 2064);
  c.requested(t0, 1);
  CHECK(c.active());
  CHECK(!c.on_frame(3840, 2064));  // Macが答える前の古いストリーム
  c.on_layout(t0, 2, 3840, 2160);
  CHECK(!c.on_frame(3840, 2064));  // まだ古いストリーム
  CHECK(c.on_frame(3840, 2160));
  CHECK(!c.active());
}

TEST(display_change_made_on_the_mac_starts_by_itself) {
  using C = app::DisplayChange::Clock;
  const C::time_point t0{};
  app::DisplayChange c;
  CHECK(!c.on_layout(t0, 1, 3840, 2160));
  CHECK(!c.on_layout(t0, 1, 3840, 2160));  // 毎回同じレイアウト
  CHECK(!c.active());
  CHECK(c.on_layout(t0, 2, 2560, 1440));  // Macのディスプレイ設定で変えた
  CHECK(c.active());
  CHECK(!c.on_frame(3840, 2160));
  CHECK(c.on_frame(2560, 1436));  // 切り取りの許容幅に収まる
}

TEST(display_change_takes_hevc_tiles_as_strips) {
  using C = app::DisplayChange::Clock;
  const C::time_point t0{};
  app::DisplayChange c;
  c.on_layout(t0, 1, 3840, 2160);
  c.requested(t0, 1);
  c.on_layout(t0, 2, 7680, 4320);
  CHECK(!c.on_frame(3840, 544, 4));   // 古いストリームのストリップ
  CHECK(!c.on_frame(7680, 1000, 4));  // 4000行。ディスプレイに足りない
  CHECK(c.on_frame(7680, 1088, 4));   // 4352行。ディスプレイと最後のストリップのパディング
}

TEST(display_change_gives_up_without_an_answer) {
  using C = app::DisplayChange::Clock;
  const C::time_point t0{};
  app::DisplayChange c;
  c.on_layout(t0, 1, 1920, 1080);
  c.requested(t0, 1);
  CHECK(!c.on_frame(1920, 1080));  // 要求のあとレイアウトが来ていないので、答えではない
  CHECK(!c.expired(t0 + std::chrono::seconds(9)));
  CHECK(c.expired(t0 + app::DisplayChange::kTimeout));
  CHECK(!c.active());
}

}  // namespace

#include "session_tests.inc"
#include "media_path_tests.inc"
#include "session_media_tests.inc"
#include "framebuffer_tests.inc"

int main(int argc, char** argv) {
  if (argc > 1 && std::strcmp(argv[1], "--fake-host") == 0) return run_fake_host(argc > 2 ? std::atoi(argv[2]) : 30);
  if (argc > 5 && std::strcmp(argv[1], "--decode-dump") == 0) {
    return decode_dump(argv[2], std::atoi(argv[3]), std::atoi(argv[4]), argv[5]);
  }
  const char* filter = argc > 1 ? argv[1] : nullptr;
  int ran = 0;
  for (auto& t : registry()) {
    if (filter && !std::strstr(t.name, filter)) continue;
    g_current = t.name;
    int before = g_failures;
    try {
      t.fn();
    } catch (const std::exception& e) {
      ++g_failures;
      std::fprintf(stderr, "  FAIL [%s] threw: %s\n", t.name, e.what());
    }
    std::printf("%s %s\n", g_failures == before ? "ok  " : "FAIL", t.name);
    ++ran;
  }
  std::printf("\n%d tests, %d checks, %d failures\n", ran, g_checks, g_failures);
  return g_failures ? 1 : 0;
}
