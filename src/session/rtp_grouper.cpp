#include "session/rtp_grouper.h"

#include <algorithm>
#include <limits>

namespace iss::session {

RtpGrouper::RtpGrouper(Output out, Timing timing) : out_(std::move(out)), timing_(timing) {}

void RtpGrouper::reset() {
  pending_.clear();
  flushed_.clear();
  dropped_at_.clear();
  last_marker_.clear();
}

// シーケンス順に並べる。65535 → 0の折り返しも扱う。循環的に見て最も大きい間隔の
// すぐ次から始めるので、65534, 65535, 0, 1のような並びでも正しい順になる。
std::vector<const RtpGrouper::Packet*> RtpGrouper::in_sequence(const Group& g) {
  std::vector<const Packet*> p;
  p.reserve(g.pkts.size());
  for (const Packet& x : g.pkts) p.push_back(&x);
  std::sort(p.begin(), p.end(), [](const Packet* a, const Packet* b) { return a->seq < b->seq; });
  if (p.size() < 2 || p.back()->seq - p.front()->seq <= 0x8000) return p;
  size_t best = 0;
  uint16_t best_gap = 0;
  for (size_t i = 0; i < p.size(); ++i) {
    const auto gap = static_cast<uint16_t>(p[(i + 1) % p.size()]->seq - p[i]->seq);
    if (gap >= best_gap) {  // 同じ間隔なら後ろのインデックス。Pythonの(gap, i)に対するmax()と同じ
      best_gap = gap;
      best = i;
    }
  }
  std::rotate(p.begin(), p.begin() + static_cast<std::ptrdiff_t>((best + 1) % p.size()), p.end());
  return p;
}

bool RtpGrouper::pending_ts(uint32_t ts) const {
  return std::any_of(pending_.begin(), pending_.end(), [ts](const auto& kv) { return kv.first.second == ts; });
}

bool RtpGrouper::has_marker(const Group& g) {
  return std::any_of(g.pkts.begin(), g.pkts.end(), [](const Packet& p) { return p.marker; });
}

bool RtpGrouper::complete(const Key& key, const Group& g) const {
  if (g.pkts.empty() || !has_marker(g)) return false;
  const auto p = in_sequence(g);
  if (!p.back()->marker) return false;
  for (size_t i = 0; i + 1 < p.size(); ++i) {
    if (static_cast<uint16_t>(p[i + 1]->seq - p[i]->seq) > 1) return false;
  }
  if (g.expected) return p.size() == g.expected;
  // グループ内が連続していても、最初のパケットの直前の損失は分からない。前の
  // マーカーがあれば、それと突き合わせて確かめる。
  const auto prev = last_marker_.find(key.first);
  return prev == last_marker_.end() || p.front()->seq == static_cast<uint16_t>(prev->second + 1);
}

// 1つのSSRCの待ちグループをデコード順に並べる。最後に使ったマーカーからの
// シーケンスの距離順で、同じなら到着時刻順（丸ごと欠けて再送されたグループは、
// 穴があると分かったきっかけのグループより後に届くため）。
std::vector<RtpGrouper::Key> RtpGrouper::ordered_keys(uint32_t ssrc) const {
  struct Entry {
    Key key;
    uint32_t dist;
    Clock::time_point arrival;
  };
  std::vector<Entry> e;
  const auto prev = last_marker_.find(ssrc);
  for (auto it = pending_.lower_bound({ssrc, 0}); it != pending_.end() && it->first.first == ssrc; ++it) {
    uint32_t dist = 0;
    if (prev != last_marker_.end()) {
      dist = it->second.pkts.empty()
                 ? std::numeric_limits<uint32_t>::max()
                 : static_cast<uint16_t>(in_sequence(it->second).front()->seq - static_cast<uint16_t>(prev->second + 1));
    }
    e.push_back({it->first, dist, it->second.arrival});
  }
  std::sort(e.begin(), e.end(), [](const Entry& a, const Entry& b) {
    return a.dist != b.dist ? a.dist < b.dist : a.arrival < b.arrival;
  });
  std::vector<Key> keys;
  keys.reserve(e.size());
  for (const Entry& x : e) keys.push_back(x.key);
  return keys;
}

void RtpGrouper::add(uint32_t ssrc, uint32_t ts, uint16_t seq, bool marker, Bytes payload, Clock::time_point now,
                     uint16_t packets) {
  const Key key{ssrc, ts};
  if (flushed_.count(key)) {  // 使い終わったグループに遅れて届いた重複
    const auto d = dropped_at_.find(key);
    if (d != dropped_at_.end() && out_.late) {
      out_.late(ssrc, seq, std::chrono::duration_cast<std::chrono::milliseconds>(now - d->second));
    }
    return;
  }
  auto [it, inserted] = pending_.try_emplace(key);
  Group& g = it->second;
  if (inserted) g.arrival = now;
  if (packets) g.expected = packets;
  if (std::none_of(g.pkts.begin(), g.pkts.end(), [&](const Packet& p) { return p.seq == seq; })) {
    g.pkts.push_back({seq, marker, std::move(payload)});
  }
  if (!has_marker(g)) return;

  const std::vector<Key> order = ordered_keys(ssrc);
  bool blocked = false;
  for (const Key& k : order) {
    if (k == key) break;
    Group& earlier = pending_.at(k);
    // 古いグループにまだマーカーがないのに新しいタイムスタンプが来た。抜けた
    // パケットはそのグループの末尾かもしれないので、修復を待つ時間を与える。
    if (!has_marker(earlier) && !earlier.repair_deadline) earlier.repair_deadline = now + timing_.repair_wait;
    blocked = blocked || earlier.repair_deadline.has_value();
  }
  if (blocked) return;
  if (!complete(key, g)) {
    if (!g.repair_deadline) g.repair_deadline = now + timing_.repair_wait;
    return;
  }
  flush(key, now);
  flush_ready(ssrc, now);
}

void RtpGrouper::flush_ready(uint32_t ssrc, Clock::time_point now) {
  for (;;) {
    const std::vector<Key> order = ordered_keys(ssrc);
    if (order.empty()) return;
    Group& g = pending_.at(order.front());
    if (!complete(order.front(), g)) {
      if (!g.repair_deadline) g.repair_deadline = now + timing_.repair_wait;
      return;
    }
    flush(order.front(), now);
  }
}

void RtpGrouper::flush(const Key& key, Clock::time_point now) {
  auto it = pending_.find(key);
  if (it == pending_.end()) return;
  Group g = std::move(it->second);
  pending_.erase(it);
  flushed_[key] = now;
  if (g.repair_deadline) ++repaired_;
  const auto p = in_sequence(g);
  std::vector<Bytes> payloads;
  payloads.reserve(p.size());
  for (const Packet* x : p) {
    if (x->marker) last_marker_[key.first] = x->seq;
    payloads.push_back(std::move(const_cast<Packet*>(x)->payload));
  }
  if (out_.access_unit) out_.access_unit(key.first, key.second, std::move(payloads));
}

void RtpGrouper::drop(const Key& key, const char* reason, Clock::time_point now) {
  auto it = pending_.find(key);
  if (it == pending_.end()) return;
  const Group g = std::move(it->second);
  pending_.erase(it);
  flushed_[key] = now;
  dropped_at_[key] = now;
  // マーカーのある捨てたグループは、境目が分かっている。そこを次のグループの基準に
  // して、後ろで待っている問題のないグループを順に出せるようにする。マーカーが
  // なければ境目は分からないので、グループ内でそろった次のグループを新しい基準にする。
  std::optional<uint16_t> marker;
  for (const Packet* x : in_sequence(g)) {
    if (x->marker) marker = x->seq;
  }
  if (marker) {
    last_marker_[key.first] = *marker;
  } else {
    last_marker_.erase(key.first);
  }
  if (out_.dropped) out_.dropped(key.first, key.second, reason, g.arrival);
}

void RtpGrouper::evict(Clock::time_point now) {
  std::vector<std::pair<Key, const char*>> expired;
  for (const auto& [key, g] : pending_) {
    if (g.repair_deadline) {
      if (now >= *g.repair_deadline) expired.push_back({key, "still incomplete after the NACK repair window"});
    } else if (now - g.arrival > timing_.marker_ttl) {
      expired.push_back({key, "no RTP marker"});
    }
  }
  std::vector<uint32_t> ssrcs;
  for (const auto& [key, reason] : expired) {
    drop(key, reason, now);
    ssrcs.push_back(key.first);
  }
  std::sort(ssrcs.begin(), ssrcs.end());
  ssrcs.erase(std::unique(ssrcs.begin(), ssrcs.end()), ssrcs.end());
  for (uint32_t s : ssrcs) flush_ready(s, now);
  for (auto it = flushed_.begin(); it != flushed_.end();) {
    it = now - it->second > timing_.dedup_ttl ? flushed_.erase(it) : std::next(it);
  }
  for (auto it = dropped_at_.begin(); it != dropped_at_.end();) {
    it = now - it->second > timing_.dedup_ttl ? dropped_at_.erase(it) : std::next(it);
  }
}

}  // namespace iss::session
