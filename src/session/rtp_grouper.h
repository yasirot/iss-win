// 復号済みのRTPパケット → デコード順のアクセスユニット（session.pyのH.264の
// グループ分けの移植。_queue_video_group_packet、_flush_group、
// _evict_stale_groups）。
//
// パケットは（SSRC、RTPタイムスタンプ）でグループにまとめる。前のグループの
// マーカーのすぐ次から途切れずに続くシーケンスを、マーカーで閉じたグループは
// そろっているので、すぐに出す。穴のあるグループはNACKによる再送を最大
// `repair_wait`まで待つ。同じSSRCの後続のグループはその後ろで待たせ、参照先より
// 先にPフレームがデコーダに渡らないようにする。待っても欠けたままのグループと、
// `marker_ttl`が過ぎてもマーカーのないグループは捨て（`dropped`で知らせる）、
// ストリームは次のそろったグループから続ける。シングルスレッドで使う。
#pragma once

#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "core/bytes.h"

namespace iss::session {

class RtpGrouper {
 public:
  using Clock = std::chrono::steady_clock;

  struct Timing {
    std::chrono::milliseconds repair_wait{75};
    std::chrono::milliseconds marker_ttl{200};
    std::chrono::milliseconds dedup_ttl{2000};  // 送り出したグループに遅れて届く重複分
  };
  struct Output {
    // ペイロードはシーケンス順。
    std::function<void(uint32_t ssrc, uint32_t ts, std::vector<Bytes>&& payloads)> access_unit;
    // `arrival`はユニットの最初のパケットが届いた時刻。
    std::function<void(uint32_t ssrc, uint32_t ts, const char* reason, Clock::time_point arrival)> dropped;
    // 捨てたあとのユニットのパケット（NACKの再送が遅すぎたのか）と、捨ててから
    // どれだけ経ったか。
    std::function<void(uint32_t ssrc, uint16_t seq, std::chrono::milliseconds after_drop)> late;
  };

  explicit RtpGrouper(Output out, Timing timing = {});

  // `packets`は送信側が示したユニットのパケット数（AppleのHEVCのヘッダ拡張）。
  // 示されなければ0。その数のパケットがマーカーまで途切れずに並んでいれば、直前の
  // パケットが欠けていてもユニットはそろっている。失ったパケットは前のユニットのもの
  // だったことになる。
  void add(uint32_t ssrc, uint32_t ts, uint16_t seq, bool marker, Bytes payload, Clock::time_point now,
           uint16_t packets = 0);
  // 期限の過ぎたグループを捨てる。約20 msごとに呼ぶ。
  void evict(Clock::time_point now);
  // すべて忘れる（新しいSSRCグループ、新しいストリーム）。
  void reset();
  size_t pending() const { return pending_.size(); }
  // このタイムスタンプのグループで、まだ終わっていないものがどれかのSSRCにある。
  bool pending_ts(uint32_t ts) const;
  // しばらく欠けていて、あとでそろったユニットの数（NACKで直ったか、順序の
  // 入れ替わり）。
  uint64_t repaired() const { return repaired_; }

 private:
  using Key = std::pair<uint32_t, uint32_t>;  // (ssrc, ts)
  struct Packet {
    uint16_t seq;
    bool marker;
    Bytes payload;
  };
  struct Group {
    std::vector<Packet> pkts;
    uint16_t expected = 0;  // 示されたパケット数。0は不明
    Clock::time_point arrival;
    std::optional<Clock::time_point> repair_deadline;
  };

  static std::vector<const Packet*> in_sequence(const Group& g);
  static bool has_marker(const Group& g);
  bool complete(const Key& key, const Group& g) const;
  std::vector<Key> ordered_keys(uint32_t ssrc) const;
  void flush(const Key& key, Clock::time_point now);
  void flush_ready(uint32_t ssrc, Clock::time_point now);
  void drop(const Key& key, const char* reason, Clock::time_point now);

  Output out_;
  Timing timing_;
  std::map<Key, Group> pending_;
  std::map<Key, Clock::time_point> flushed_;
  std::map<Key, Clock::time_point> dropped_at_;  // flushed_の部分集合
  std::map<uint32_t, uint16_t> last_marker_;
  uint64_t repaired_ = 0;
};

}  // namespace iss::session
