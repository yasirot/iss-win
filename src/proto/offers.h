// AVCMediaStreamNegotiatorのオファー組み立てとアンサー解析、それに0x1c
// MediaStreamConfigurationメッセージ（offers.pyとnegotiation.pyのbuild_0x1cの移植）。
// 出力はPython版クライアントとバイト単位で一致する。ただし呼び出しごとに変わる
// フィールド（session id、タイムスタンプ、CallIDのUUID）と、blobのzlib符号化は除く
// （ここでは無圧縮ブロック、Python版はレベル6。どちらも同じバイト列を表す正しい
// zlibストリーム）。
#pragma once

#include <array>
#include <optional>
#include <string>
#include <vector>

#include "core/bytes.h"

namespace iss::proto {

enum class VideoCodec { Both, Hevc, Avc };

struct OfferOptions {
  VideoCodec codec = VideoCodec::Both;
  std::optional<bool> ltrp;            // 既定ではcodec == Avc以外でオン
  std::optional<int> tiles_per_frame;  // 既定はAvcで1、それ以外は4
  bool audio_enabled = true;
  std::optional<int64_t> audio_f4;     // ISS_AUDIO_F4で上書き
  std::string client_name = "iShareScreen 0.1.0";
  std::string hw_model = "Windows-AMD64";
  std::string avc_version = "1.0.0";
  std::string os_build = "11";
  // 2なら2本目のビデオストリーム（2台目の仮想ディスプレイ）もオファーする。
  int video_streams = 1;
  // 実験用（HEVC 4:2:0を得る方法を探している）。VideoSettingsのfield 8
  // （63、ビットマスクらしい）と、HEVCになるバンクのfield 1 / field 4 / パラメータ
  // 文字列（100 / 14 / kAvcParams）。未設定ならAppleの値。
  std::optional<uint64_t> video_f8;
  std::optional<uint64_t> hevc_bank_f1, hevc_bank_f4;
  std::optional<std::string> hevc_bank_params;

  bool ltrp_enabled() const;
  int tiles() const;

  // 既定値に加えて、Python版クライアントと同じ環境変数を読む。
  // ISS_VIDEO_CODEC, ISS_LTRP, ISS_TILES_PER_FRAME, ISS_AUDIO_F4と、実験用の
  // ISS_VIDEO_F8, ISS_HEVC_BANK_F1, ISS_HEVC_BANK_F4,
  // ISS_HEVC_BANK_PARAMS, ISS_HW_MODEL。
  static OfferOptions from_env();
};

// field 6のオーディオ記述を有効にするか決める値（offers.py参照）。
inline constexpr int64_t kAudioF4On = 24191;
inline constexpr int64_t kAudioF4Off = 1000;

// mode 7はビデオ、mode 8はオーディオ
Bytes build_mediablob(int mode, uint32_t session_id, uint64_t timestamp_ns, const OfferOptions& opt);
Bytes build_remote_endpoint_info(const OfferOptions& opt);
// 圧縮済みのmedia blobを包むオファーplist。
Bytes build_offer_plist(int mode, const Bytes& compressed_blob, const Bytes& endpoint_info,
                        const std::string& call_id);

struct Offers {
  Bytes video;
  Bytes audio;
  Bytes video2;  // 2本目のビデオストリーム。空ならなし
};
// 呼ぶたびにsession id、タイムスタンプ、CallIDを新しく作る。
Offers create_offers(const OfferOptions& opt);

// こちらがオファーで示したSSRC（ビデオはfield 5→1、オーディオはfield 3→1）。
std::optional<uint32_t> extract_offer_ssrc(const Bytes& offer_plist, bool is_video);

struct CanvasDims {
  int width = 0;
  int height = 0;
  int tiles = 0;
  std::optional<int> ltrp;  // 交渉で決まったltrpEnabled（アンサーのF5.f7）。あるときだけ
  bool valid() const { return width && height; }
};
// サーバーの0x1cアンサーから取り出す(canvas_w, canvas_h, tiles)。エンコーダの
// 準備がまだならすべて0（呼び出し側が問い合わせ直す）。
CanvasDims extract_canvas_dims(const uint8_t* msg, size_t n);
inline CanvasDims extract_canvas_dims(const Bytes& msg) { return extract_canvas_dims(msg.data(), msg.size()); }
// アンサー内のビデオキャンバスすべてを順に返す（ビデオストリームごとに1つ）。
std::vector<CanvasDims> extract_all_canvas_dims(const uint8_t* msg, size_t n);

// 方向ごとのSRTPマスターキーとソルトのblob（32 + 14バイト）。
struct NegotiationKeys {
  Bytes audio_key_v;  // ビューア → サーバー
  Bytes audio_key_s;  // サーバー → ビューア
  Bytes video_key_v;
  Bytes video_key_s;
  Bytes video2_key_v;  // 2本目のビデオストリーム用
  Bytes video2_key_s;
};
NegotiationKeys random_negotiation_keys();

struct Msg1cOptions {
  bool alt_session = false;
  bool legacy_cursor = false;  // ISS_LEGACY_CURSOR=1でカーソルをホスト側で映像に焼き込ませる
  Bytes video2_offer;          // 2本目のビデオストリーム（keys.video2_*）。空ならなし
};
Bytes build_0x1c(const Bytes& audio_offer, const Bytes& video_offer, const NegotiationKeys& keys,
                 const std::array<uint8_t, 16>& call_uuid, const Msg1cOptions& opt);

// ランダムなRFC 4122 v4 UUID（バイト列）と、その大文字の文字列表現。
std::array<uint8_t, 16> random_uuid4();
std::string uuid_to_upper_string(const std::array<uint8_t, 16>& u);

}  // namespace iss::proto
