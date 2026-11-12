// RTCPフィードバックのビルダーとSRのパーサー（rtcp.pyの移植）。こちらが作るのは
// 受信側のフィードバックだけ。ほかに、ホストのAVConferenceの生存確認で送信者として
// 認めてもらうための空のSRを作る。
//
//   PT=192  旧来のFIR（RFC 2032）。純正ビューアが送るのはこれ
//   PT=200  Sender Report      PT=201  Receiver Report
//   PT=204  APP: AppleのLTR ack（subtype 5）
//   PT=205  NACK (FMT 1)       PT=206  PLI (FMT 1) / FIR (FMT 4)
#pragma once

#include <cstdint>
#include <vector>

#include "core/bytes.h"

namespace iss::proto::rtcp {

Bytes build_fir(uint32_t sender_ssrc, uint32_t target_ssrc, uint8_t seq_nr);
Bytes build_fir_legacy(uint32_t target_ssrc);
Bytes build_pli(uint32_t sender_ssrc, uint32_t media_ssrc);
// PIDから16以内に続く番号はそのPIDのBLPにまとめる。`lost`が空なら空を返す。
Bytes build_nack(uint32_t sender_ssrc, uint32_t media_ssrc, std::vector<uint16_t> lost);
Bytes build_app_ltrp(uint32_t sender_ssrc, uint32_t ltr_id);
// `unix_time`は1970年からの秒数（壁時計）。
Bytes build_empty_sr(uint32_t sender_ssrc, double unix_time);

struct ReportBlock {
  uint32_t ssrc = 0;
  uint32_t roc = 0;
  uint16_t max_seq = 0;
  uint32_t lsr = 0;   // 直近のSRのNTP時刻の中央32ビット
  uint32_t dlsr = 0;  // そのSRからの経過時間。単位は1/65536秒
};
// 最大31ブロック。0個なら8バイトの空のRR。
Bytes build_rr(uint32_t sender_ssrc, const std::vector<ReportBlock>& blocks = {});

// ホストは、RRで始まる複合パケットに入ったフィードバックしか受け付けない。
// 返すのは空のRR || payload。
Bytes compound_with_rr(uint32_t sender_ssrc, const Bytes& payload);

struct SrArrival {
  uint32_t ssrc;
  uint32_t ntp_mid32;
};
// 複合RTCPバッファに含まれるSender Report。
std::vector<SrArrival> parse_sr_arrivals(const Bytes& data);

}  // namespace iss::proto::rtcp
