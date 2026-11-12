// AppleのRTPペイロード形式からNALを組み立て直す（media/nalu.pyと
// media/avc_nalu.pyの移植）。
//
// HEVCはRFC 7798と違う点がある。APはNALヘッダーの後ろにDONLを1つだけ持ち、
// DONDは持たない。FUの断片はどれもDONLを持つ。単独のNALUもDONLを持つので、
// 取り除く必要がある。H.264はRFC 6184どおりで、FU-Aと単独のNALにはDONがない。
// デコーダーの設定は、avc1/avcCを包んだAppleの0x92パケットで届く。
#pragma once

#include <cstdint>
#include <optional>
#include <vector>

#include "core/bytes.h"

namespace iss::media {

// ── HEVC ─────────────────────────────────────────────────────────────────
inline constexpr int HEVC_NAL_VPS = 32;
inline constexpr int HEVC_NAL_SPS = 33;
inline constexpr int HEVC_NAL_PPS = 34;
inline constexpr int HEVC_NAL_AGGREGATION = 48;
inline constexpr int HEVC_NAL_FRAGMENTATION = 49;

inline int hevc_nal_type(uint8_t b0) { return (b0 >> 1) & 0x3F; }
// IRAPはBLA_W_LP (16) .. CRA_NUT (21)
inline bool hevc_is_irap(int t) { return t >= 16 && t <= 21; }

// 同じタイムスタンプのRTPペイロード（シーケンス順）→ スタートコードなしのNALU。
// 不正なものは知らせずに捨てる。
std::vector<Bytes> hevc_reassemble_group(const std::vector<Bytes>& payloads);
// RTPペイロード1つのDONL、またはDONLを持つ最初のパケットのDONL。
std::optional<uint16_t> hevc_payload_donl(const Bytes& payload);
std::optional<uint16_t> hevc_first_donl(const std::vector<Bytes>& payloads);

struct HevcSpsInfo {
  int width = 0, height = 0;  // 輝度のサンプル数。conformance windowを引いたあとの値
  int chroma_format_idc = 0;  // 1 = 4:2:0, 3 = 4:4:4
  int level_idc = 0;          // レベルの30倍（153 = 5.1, 156 = 5.2, 180 = 6.0）
};
// SPSのNAL（2バイトのヘッダーを含む）から、画像サイズ、クロマ形式、レベルを
// 取り出す。SPS以外はnullopt。
std::optional<HevcSpsInfo> parse_hevc_sps(const Bytes& nal);

// ── H.264 ────────────────────────────────────────────────────────────────
inline constexpr int AVC_NAL_SLICE_NONIDR = 1;
inline constexpr int AVC_NAL_SLICE_IDR = 5;
inline constexpr int AVC_NAL_SPS = 7;
inline constexpr int AVC_NAL_PPS = 8;
inline constexpr int AVC_NAL_STAP_A = 24;
inline constexpr int AVC_NAL_FU_A = 28;
inline constexpr int AVC_NAL_FU_B = 29;
inline constexpr uint8_t APPLE_AVC_CONFIG_MARKER = 0x92;

inline int avc_nal_type(uint8_t b0) { return b0 & 0x1F; }

std::vector<Bytes> avc_reassemble(const std::vector<Bytes>& payloads);

// DPBをそこから始め直すNALか。type 5のIDRか、type 1のNALに入った
// Iスライス（slice_type 2 / 7）。後者がAppleのふだんのキーフレーム。
bool avc_nal_is_keyframe(const Bytes& nalu);
// キーフレームの始まりを含むRTPペイロードか。そのNAL全体、その最初の断片
// （FU-A）、それを含む集約パケット（STAP-A）のどれか。
bool avc_payload_starts_keyframe(const Bytes& payload);

// Annex-Bのアクセスユニット（4バイトのスタートコード）を扱う関数。
bool avc_au_is_keyframe(const Bytes& au_annexb);
bool avc_au_has_sps(const Bytes& au_annexb);

struct AvcConfig {
  Bytes sps;
  Bytes pps;
};
// Appleの0x92設定パケットから取り出したSPS/PPS（avc1サンプルエントリ → avcC）。
std::optional<AvcConfig> parse_avc_config(const Bytes& payload);

// AppleのSPSはレベル5.2でmax_num_ref_frames = 8と宣言するが、エンコーダーは
// 最大9枚（short-term 7枚 + LTR 2枚）を参照する。するとlibavが1枚を捨て、
// 次のキーフレームまで後続のフレームがにじむ。そこでSPSをレベル6.0、
// max_num_ref_frames = 16に書き換える（avc._patch_avc_sps_dpbの移植で、
// NALヘッダー以降の生のビットを直接いじる）。scaling listや途中で切れたSPSなど、
// 想定外のものはSPSをそのまま返す。
Bytes patch_avc_sps_dpb(const Bytes& sps);

}  // namespace iss::media
