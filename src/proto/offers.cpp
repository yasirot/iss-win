#include "proto/offers.h"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <chrono>
#include <climits>
#include <cstdlib>
#include <format>
#include <stdexcept>
#include <string_view>

#include "core/log.h"
#include "crypto/crypto.h"
#include "proto/protobuf.h"
#include "proto/rfb.h"
#include "util/bplist.h"
#include "util/zlib.h"

namespace iss::proto {
namespace {

constexpr size_t kSrtpKeyBlobLen = 46;  // 32バイトのマスターキー + 14バイトのソルト

// Appleの標準的なf9オーディオ設定ティアの一覧。f1はエントリの種類を表す。
//   0       ネットワークビットレート上限つきの主ティア（f2 = bps、f3 = バッファ上限）
//   16/4/1  コーデック固有のマーカー（CELT-NB、SILKなど）
//   4074    ヘッダーマーカー
// 75Mと100MはSequoia標準のAVConferenceが省くHPティア。サーバーにHPティアを
// 選ばせるため常に送る。
struct AudioTier {
  uint64_t f1, f2;
  int64_t f3;  // 負ならフィールドなし
};
constexpr AudioTier kAudioF9Tiers[] = {
    {0, 40'000'000, 12288},     // 40M
    {0, 6'000'000, 131072},     // 6M
    {4074, 0, 16384},           // ヘッダーマーカー
    {16, 4100, -1},             // CELT-NB 4100
    {0, 75'000'000, 524288},    // 75M CELT-FB <- HPティア
    {0, 20'000'000, 98304},     // 20M
    {4, 6500, -1},              // SILK 6500
    {0, 60'000'000, 262144},    // 60M
    {1, 299, -1},               // 299
    {0, 100'000'000, 1048576},  // 100M CELT-FB <- HPティア
};

// `LTR;`はlong-term referenceに対応していることを示す。AVCでは外しておく必要がある
// （OfferOptions::ltrp_enabled参照）。
constexpr std::string_view kHevcParamsLtr =
    "FLS;MS:-1;LF:-1;LTR;CABAC;POS:0;EOD:1;HTS:2;RR:3;AR:16/9,5/8;XR:16/9,5/8;";
constexpr std::string_view kHevcParamsNoLtr =
    "FLS;MS:-1;LF:-1;CABAC;POS:0;EOD:1;HTS:2;RR:3;AR:16/9,5/8;XR:16/9,5/8;";
constexpr std::string_view kAvcParams = "FLS;LF:-1;POS:5;EOD:1;HTS:2;RR:3;POSE:4;AR:16/9,5/8;XR:16/9,5/8;";

void put_audio_f9(ByteWriter& w) {
  for (const AudioTier& t : kAudioF9Tiers) {
    ByteWriter body;
    pb::field_varint(body, 1, t.f1);
    pb::field_varint(body, 2, t.f2);
    if (t.f3 >= 0) pb::field_varint(body, 3, static_cast<uint64_t>(t.f3));
    pb::field_bytes(w, 9, body.data());
  }
}

Bytes res_entry(uint64_t f2) {
  ByteWriter w;
  pb::field_varint(w, 1, 1);
  pb::field_varint(w, 2, f2);
  pb::field_varint(w, 3, 50115);
  pb::field_varint(w, 4, 0);
  return w.take();
}

std::optional<std::string> env(const char* name) {
  char* v = nullptr;
  size_t n = 0;
  if (_dupenv_s(&v, &n, name) || !v) return std::nullopt;
  std::string s(v);
  std::free(v);
  return s;
}

template <class T>
std::optional<T> parse_int(std::string_view s) {
  while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) s.remove_prefix(1);
  while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) s.remove_suffix(1);
  if (!s.empty() && s.front() == '+') s.remove_prefix(1);
  T v{};
  auto [end, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
  if (ec != std::errc{} || end != s.data() + s.size()) return std::nullopt;
  return v;
}

int to_int(uint64_t v) { return v > INT_MAX ? 0 : static_cast<int>(v); }

// `at`から始まる候補のbplist 1つからキャンバス寸法を取り出す。plistの長さは
// わからないので、パースできるまで終端オフセットを順に全部試す（Python版クライアントは
// 2ずつ進めるので、奇数長のplistしか見つからない）。
CanvasDims canvas_from_plist_at(const uint8_t* at, const uint8_t* end) {
  std::optional<plist::Value> root;
  for (size_t len = 1; len <= static_cast<size_t>(end - at) && !root; ++len) root = plist::parse_binary(at, len);
  if (!root || root->type != plist::Value::Type::Dict) return {};
  const plist::Value* blob = root->get("avcMediaStreamNegotiatorMediaBlob");
  if (!blob || blob->type != plist::Value::Type::Data || blob->data.empty()) return {};
  auto dec = zlib::decompress(blob->data);
  if (!dec) return {};

  // トップレベルのF5がビデオ設定。F4はキャンバスの幅、F5は高さ（輝度
  // サンプル数）、F6はタイル数、F7は交渉で決まったltrpEnabled。
  CanvasDims d;
  pb::for_each_field(dec->data(), dec->size(), [&](const pb::Field& f) {
    if (f.wire_type != 2 || f.number != 5) return;
    pb::for_each_field(f.data, f.size, [&](const pb::Field& s) {
      if (s.wire_type != 0) return;
      switch (s.number) {
        case 4: d.width = to_int(s.varint); break;
        case 5: d.height = to_int(s.varint); break;
        case 6: d.tiles = to_int(s.varint); break;
        case 7: d.ltrp = to_int(s.varint); break;
        default: break;
      }
    });
  });
  return d;
}

}  // namespace

// ── オプション ──────────────────────────────────────────────────────────────

// LTRPをエンドツーエンドで実装しているのはHEVCだけ。H.264の経路にはackを返せる
// きれいなDONLがないので、そこでLTRPを示すとプロトコルの食い違いになる。
bool OfferOptions::ltrp_enabled() const { return codec != VideoCodec::Avc && ltrp.value_or(true); }

// AVCの既定は1タイル。Appleの4タイルのストリームはタイルをまたいで参照するが、
// libavのH.264コンテキスト1つを共有すると、その参照を違うタイルに対して解決してしまう。
int OfferOptions::tiles() const { return std::max(1, tiles_per_frame.value_or(codec == VideoCodec::Avc ? 1 : 4)); }

OfferOptions OfferOptions::from_env() {
  OfferOptions o;
  if (auto v = env("ISS_VIDEO_CODEC")) {
    std::string c = *v;
    std::transform(c.begin(), c.end(), c.begin(), [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    if (c == "avc") o.codec = VideoCodec::Avc;
    else if (c == "hevc") o.codec = VideoCodec::Hevc;
  }
  if (auto v = env("ISS_LTRP")) o.ltrp = *v != "0";
  if (auto v = env("ISS_TILES_PER_FRAME")) o.tiles_per_frame = parse_int<int>(*v);
  if (auto v = env("ISS_AUDIO_F4")) o.audio_f4 = parse_int<int64_t>(*v);
  if (auto v = env("ISS_VIDEO_F8")) o.video_f8 = parse_int<uint64_t>(*v);
  if (auto v = env("ISS_HEVC_BANK_F1")) o.hevc_bank_f1 = parse_int<uint64_t>(*v);
  if (auto v = env("ISS_HEVC_BANK_F4")) o.hevc_bank_f4 = parse_int<uint64_t>(*v);
  if (auto v = env("ISS_HEVC_BANK_PARAMS")) o.hevc_bank_params = *v;
  if (auto v = env("ISS_HW_MODEL")) o.hw_model = *v;
  return o;
}

// ── オファーの組み立て ───────────────────────────────────────────────────

Bytes build_mediablob(int mode, uint32_t session_id, uint64_t timestamp_ns, const OfferOptions& opt) {
  ByteWriter desc;
  uint32_t desc_field = 0;
  if (mode == 7) {
    const bool ltrp_on = opt.ltrp_enabled();
    const Bytes res = res_entry(1), res_alt = res_entry(2);

    ByteWriter hevc_bank;
    pb::field_varint(hevc_bank, 1, 123);
    for (const Bytes* e : {&res, &res_alt, &res, &res_alt}) pb::field_bytes(hevc_bank, 2, *e);
    pb::field_bytes(hevc_bank, 3, ltrp_on ? kHevcParamsLtr : kHevcParamsNoLtr);
    pb::field_varint(hevc_bank, 4, 1);

    ByteWriter avc_bank;
    pb::field_varint(avc_bank, 1, opt.hevc_bank_f1.value_or(100));
    pb::field_bytes(avc_bank, 2, res);
    pb::field_bytes(avc_bank, 2, res_alt);
    pb::field_bytes(avc_bank, 3, opt.hevc_bank_params ? std::string_view(*opt.hevc_bank_params) : kAvcParams);
    pb::field_varint(avc_bank, 4, opt.hevc_bank_f4.value_or(14));

    // 危険: バンクの名前は持っているパラメータ文字列から付けたものだが、サーバーの
    // アンサーは逆になる（実機で確認済み）。HEVCのパラメータを持つfield1=123ではH.264 4:2:0、
    // AVCのパラメータを持つfield1=100ではHEVC 4:4:4になる。出力で選ぶこと。名前どおりに
    // 「直す」のはやめること。
    const Bytes& bank_yields_h264 = hevc_bank.data();
    const Bytes& bank_yields_hevc = avc_bank.data();

    // VideoSettingsのフィールド番号。2 = allowRTCPFB、6 = tilesPerFrame、7 = ltrpEnabled。
    pb::field_varint(desc, 1, session_id);
    pb::field_varint(desc, 2, ltrp_on ? 1 : 0);
    switch (opt.codec) {
      case VideoCodec::Avc: pb::field_bytes(desc, 3, bank_yields_h264); break;
      case VideoCodec::Hevc: pb::field_bytes(desc, 3, bank_yields_hevc); break;
      case VideoCodec::Both:
        // Appleとバイト単位で同じ順序（123、次に100）。サーバーはHEVC 4:4:4を選ぶ。
        pb::field_bytes(desc, 3, hevc_bank.data());
        pb::field_bytes(desc, 3, avc_bank.data());
        break;
    }
    pb::field_varint(desc, 6, static_cast<uint64_t>(opt.tiles()));
    pb::field_varint(desc, 7, ltrp_on ? 1 : 0);
    pb::field_varint(desc, 8, opt.video_f8.value_or(63));
    pb::field_varint(desc, 9, 1);
    pb::field_varint(desc, 12, 1);
    desc_field = 5;
  } else if (mode == 8) {
    // field4はpreferredMediaBitRate。画面共有のオーディオには約21 kbpsのティアが
    // 1つしかなく、その下限の約5 kbpsを下回るとホストはオーディオを送らない。
    // 回線上でオーディオを止める方法はこれしかない。
    const int64_t f4 = opt.audio_f4.value_or(opt.audio_enabled ? kAudioF4On : kAudioF4Off);
    pb::field_varint(desc, 1, session_id);
    pb::field_varint(desc, 2, 0);
    pb::field_varint(desc, 3, 0);
    pb::field_varint(desc, 4, static_cast<uint64_t>(f4));
    pb::field_varint(desc, 5, 0);
    pb::field_varint(desc, 6, 0);
    desc_field = 3;
  } else {
    throw std::invalid_argument(std::format("unsupported negotiation mode {}", mode));
  }

  ByteWriter w;
  pb::field_varint(w, 1, 1);
  pb::field_varint(w, 2, 1);
  pb::field_bytes(w, desc_field, desc.data());
  pb::field_bytes(w, 6, opt.client_name);
  pb::field_varint(w, 8, 0);
  put_audio_f9(w);
  pb::field_varint(w, 13, timestamp_ns);
  pb::field_varint(w, 14, 2);
  pb::field_varint(w, 16, 0);
  pb::field_varint(w, 18, 1);
  return w.take();
}

// AVConference向けの情報にすぎない。0x1c全体がenc1103で包まれるので、
// これはデーモンにしか届かない。
Bytes build_remote_endpoint_info(const OfferOptions& opt) {
  ByteWriter w;
  w.u8(0x08).u8(0x00);  // f1 = 0
  w.u8(0x10).u8(0x01);  // f2 = 1
  auto put_str = [&](uint8_t tag, const std::string& s) {
    const size_t n = std::min<size_t>(s.size(), 127);
    w.u8(tag).u8(static_cast<uint8_t>(n)).raw(s.data(), n);
  };
  put_str(0x1A, opt.hw_model);
  put_str(0x22, opt.avc_version);
  put_str(0x2A, opt.os_build);
  return w.take();
}

Bytes build_offer_plist(int mode, const Bytes& compressed_blob, const Bytes& endpoint_info,
                        const std::string& call_id) {
  using plist::Value;
  Value root = Value::make_dict();
  root.set("avcMediaStreamOptionRemoteEndpointInfo", Value::bytes(endpoint_info))
      .set("avcMediaStreamNegotiatorMode", Value::integer(mode))
      .set("avcMediaStreamNegotiatorMediaBlob", Value::bytes(compressed_blob))
      .set("avcMediaStreamOptionCallID", Value::string(call_id));
  return plist::write_binary(root);
}

Offers create_offers(const OfferOptions& opt) {
  const Bytes endpoint = build_remote_endpoint_info(opt);
  auto make = [&](int mode) {
    const uint32_t session_id = rd_be32(crypto::random_bytes(4).data());
    const auto now = std::chrono::system_clock::now().time_since_epoch();
    const auto ts = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(now).count());
    const Bytes blob = build_mediablob(mode, session_id, ts, opt);
    return build_offer_plist(mode, zlib::compress_stored(blob), endpoint, uuid_to_upper_string(random_uuid4()));
  };
  Offers o{make(7), make(8)};
  if (opt.video_streams >= 2) o.video2 = make(7);
  return o;
}

// ── アンサーの解析 ───────────────────────────────────────────────────────

// AVConferenceは交渉したSSRCからのRTP/RTCPしか受け付けない。それ以外だと
// 約30秒後に何の知らせもなくnoRemotePacketsTimeoutになる。
std::optional<uint32_t> extract_offer_ssrc(const Bytes& offer_plist, bool is_video) {
  auto root = plist::parse_binary(offer_plist);
  if (!root) return std::nullopt;
  const plist::Value* blob = root->get("avcMediaStreamNegotiatorMediaBlob");
  if (!blob || blob->type != plist::Value::Type::Data) return std::nullopt;
  auto dec = zlib::decompress(blob->data);
  if (!dec) return std::nullopt;

  const uint32_t target = is_video ? 5 : 3;
  std::optional<uint32_t> ssrc;
  pb::for_each_field(dec->data(), dec->size(), [&](const pb::Field& f) {
    if (ssrc || f.wire_type != 2 || f.number != target) return;
    size_t pos = 0;
    const uint64_t tag = pb::read_varint(f.data, f.size, pos);
    if ((tag & 7) == 0 && (tag >> 3) == 1) ssrc = static_cast<uint32_t>(pb::read_varint(f.data, f.size, pos));
  });
  return ssrc;
}

// ビデオのアンサーのprotobufは、復号したメッセージのどこかに埋め込まれた
// bplistの中にある。"bplist"が現れる箇所をすべて調べる。
CanvasDims extract_canvas_dims(const uint8_t* msg, size_t n) {
  const std::vector<CanvasDims> all = extract_all_canvas_dims(msg, n);
  if (all.empty()) return {};
  if (all.front().ltrp) log::info("negotiated ltrpEnabled (answer F5.f7) = {}", *all.front().ltrp);
  return all.front();
}

std::vector<CanvasDims> extract_all_canvas_dims(const uint8_t* msg, size_t n) {
  std::vector<CanvasDims> out;
  if (n == 0 || msg[0] != 0x00) return out;
  static constexpr std::string_view kMagic = "bplist";
  const uint8_t* const end = msg + n;
  for (const uint8_t* at = msg;; at += kMagic.size()) {
    at = std::search(at, end, kMagic.begin(), kMagic.end());
    if (at == end) return out;
    if (CanvasDims d = canvas_from_plist_at(at, end); d.valid()) out.push_back(d);
  }
}

// ── 0x1c MediaStreamConfiguration ────────────────────────────────────────

NegotiationKeys random_negotiation_keys() {
  return NegotiationKeys{
      crypto::random_bytes(kSrtpKeyBlobLen), crypto::random_bytes(kSrtpKeyBlobLen),
      crypto::random_bytes(kSrtpKeyBlobLen), crypto::random_bytes(kSrtpKeyBlobLen),
      crypto::random_bytes(kSrtpKeyBlobLen), crypto::random_bytes(kSrtpKeyBlobLen),
  };
}

// AVConferenceの_buildOfferMessageと同じレイアウトにする。
//   +0x00 u8      メッセージ種別0x1c
//   +0x02 u16 BE  MS = audio_size + video_size + 0xd8
//   +0x04 u16 BE  version = 3
//   +0x06 u32 BE  設定フラグ
//   +0x0a u16 BE  audio_size
//   +0x0c u16 BE  video_size
//   +0x14 16 B    CallIDのUUID
//   +0x24 46 B    viewer->serverのオーディオキー
//   +0x52 46 B    server->viewerのオーディオキー
//   +0x80         オーディオのオファーplist
//   +var  46 B    viewer->serverのビデオキー、続いてserver->viewerの46 B
//   +0x5c         ビデオのオファーplist
// 2本目のビデオストリームがあるとき（+0x0eにu16 BEでそのサイズ）は、そのキー2つと
// オファーを1本目の後ろに置く。
Bytes build_0x1c(const Bytes& audio_offer, const Bytes& video_offer, const NegotiationKeys& keys,
                 const std::array<uint8_t, 16>& call_uuid, const Msg1cOptions& opt) {
  for (const Bytes* k : {&keys.audio_key_v, &keys.audio_key_s, &keys.video_key_v, &keys.video_key_s}) {
    if (k->size() != kSrtpKeyBlobLen) throw std::invalid_argument("0x1c: SRTP key blobs must be 46 bytes");
  }
  const size_t v2s = opt.video2_offer.size();
  if (v2s && (keys.video2_key_v.size() != kSrtpKeyBlobLen || keys.video2_key_s.size() != kSrtpKeyBlobLen)) {
    throw std::invalid_argument("0x1c: SRTP key blobs must be 46 bytes");
  }
  const size_t as = audio_offer.size(), vs = video_offer.size();
  const size_t ms = as + vs + 0xD8 + (v2s ? 0x5C + v2s : 0);
  if (ms > 0xFFFF) throw std::invalid_argument(std::format("0x1c: offers too large ({} + {} bytes)", as, vs));

  // エージェントのSetServerStreamConfiguration_rpcに渡す設定ビットマスク
  //   bit 0 = ストリーム1を60 fps（常にオン）
  //   bit 1 = ストリーム2を60 fps（追加の画質ティア）
  //   bit 2 = フレームバッファにカーソルを入れない。ローカルのenc-1104オーバーレイが
  //           描くので、カーソルが動いてもビデオフレームは出ない。これがないと
  //           alt-sessionの経路では左上に固まったカーソルが焼き込まれる。
  uint32_t config_flags = 3;
  if (opt.alt_session) {
    config_flags = (config_flags & ~2u) | 4;
  } else if (!opt.legacy_cursor) {
    config_flags |= 4;
  }

  Bytes buf(ms + 4, 0);
  buf[0] = rfb::CLI_MEDIA_NEGOTIATION;
  wr_be16(&buf[2], static_cast<uint16_t>(ms));
  wr_be16(&buf[4], 3);
  // わざとBIG-endianにしている。ホストはこのワードをバイト順を入れ替えずに
  // ストリーミングエージェントへ渡す。エージェントは、IPC境界でバイト順が入れ替わった
  // 値の`& 4`を調べる。little-endianだとdo_not_send_cursorが立たない（カーソルが二重になる）。
  wr_be32(&buf[6], config_flags);
  wr_be16(&buf[10], static_cast<uint16_t>(as));
  wr_be16(&buf[12], static_cast<uint16_t>(vs));
  std::copy(call_uuid.begin(), call_uuid.end(), buf.begin() + 0x14);
  std::copy(keys.audio_key_v.begin(), keys.audio_key_v.end(), buf.begin() + 0x24);
  std::copy(keys.audio_key_s.begin(), keys.audio_key_s.end(), buf.begin() + 0x52);
  std::copy(audio_offer.begin(), audio_offer.end(), buf.begin() + 0x80);
  const size_t vo = 0x80 + as;
  std::copy(keys.video_key_v.begin(), keys.video_key_v.end(), buf.begin() + vo);
  std::copy(keys.video_key_s.begin(), keys.video_key_s.end(), buf.begin() + vo + 0x2E);
  std::copy(video_offer.begin(), video_offer.end(), buf.begin() + vo + 0x5C);
  if (v2s) {
    wr_be16(&buf[14], static_cast<uint16_t>(v2s));
    const size_t v2o = vo + 0x5C + vs;
    std::copy(keys.video2_key_v.begin(), keys.video2_key_v.end(), buf.begin() + v2o);
    std::copy(keys.video2_key_s.begin(), keys.video2_key_s.end(), buf.begin() + v2o + 0x2E);
    std::copy(opt.video2_offer.begin(), opt.video2_offer.end(), buf.begin() + v2o + 0x5C);
  }
  return buf;
}

std::array<uint8_t, 16> random_uuid4() {
  const Bytes r = crypto::random_bytes(16);
  std::array<uint8_t, 16> u{};
  std::copy(r.begin(), r.end(), u.begin());
  u[6] = static_cast<uint8_t>((u[6] & 0x0F) | 0x40);  // バージョン4
  u[8] = static_cast<uint8_t>((u[8] & 0x3F) | 0x80);  // RFC 4122のバリアント
  return u;
}

std::string uuid_to_upper_string(const std::array<uint8_t, 16>& u) {
  static constexpr char kHex[] = "0123456789ABCDEF";
  std::string s;
  s.reserve(36);
  for (size_t i = 0; i < u.size(); ++i) {
    if (i == 4 || i == 6 || i == 8 || i == 10) s.push_back('-');
    s.push_back(kHex[u[i] >> 4]);
    s.push_back(kHex[u[i] & 0xF]);
  }
  return s;
}

}  // namespace iss::proto
