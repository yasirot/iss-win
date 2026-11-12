// RTPのグループ化と、ループバックの「Mac」相手のセッション全体。session_tests.incの
// ハンドシェイクサーバーのあと、テストクリップのH.264をSRTPでUDPに流す。
// test_main.cppがmedia_path_tests.incの後に読み込む。
#include <atomic>
#include <chrono>

#include "media/bitstream.h"
#include "session/control_messages.h"
#include "session/picture_assembler.h"
#include "session/rtp_grouper.h"
#include "session/session.h"
#include "util/zlib.h"

namespace {

using namespace std::chrono_literals;

// ── RtpGrouper ───────────────────────────────────────────────────────────

struct GrouperProbe {
  std::vector<std::pair<uint32_t, std::vector<Bytes>>> units;  // (ts, payloads)
  std::vector<uint32_t> dropped;                               // ts
  session::RtpGrouper g{{[this](uint32_t, uint32_t ts, std::vector<Bytes>&& p) { units.push_back({ts, std::move(p)}); },
                         [this](uint32_t, uint32_t ts, const char*, session::RtpGrouper::Clock::time_point) {
                           dropped.push_back(ts);
                         }}};
  session::RtpGrouper::Clock::time_point t0 = session::RtpGrouper::Clock::now();

  void add(uint32_t ts, uint16_t seq, bool marker, std::chrono::milliseconds at = 0ms) {
    g.add(7, ts, seq, marker, Bytes{static_cast<uint8_t>(seq)}, t0 + at);
  }
  std::vector<uint32_t> unit_ts() const {
    std::vector<uint32_t> out;
    for (const auto& u : units) out.push_back(u.first);
    return out;
  }
};

TEST(grouper_in_order_and_reordered) {
  GrouperProbe p;
  p.add(100, 10, false);
  p.add(100, 11, true);
  p.add(200, 14, true);  // 最初のパケットより先に届く
  p.add(200, 12, false);
  p.add(200, 13, false);
  CHECK(p.unit_ts() == std::vector<uint32_t>({100, 200}));
  CHECK(p.units.size() == 2 && p.units[1].second == std::vector<Bytes>({{12}, {13}, {14}}));
  CHECK(p.dropped.empty() && p.g.pending() == 0);
}

TEST(grouper_waits_for_a_repair_and_keeps_order) {
  GrouperProbe p;
  p.add(100, 10, true);
  p.add(200, 11, false);
  p.add(200, 13, true);  // 12が欠けている
  p.add(300, 14, true);  // 200の後ろで待つ
  CHECK(p.unit_ts() == std::vector<uint32_t>({100}));
  CHECK(p.g.pending_ts(200) && !p.g.pending_ts(100));
  p.g.evict(p.t0 + 50ms);  // 修復を待つ時間内
  CHECK(p.dropped.empty());
  p.add(200, 12, false, 60ms);  // NACKによる再送
  CHECK(p.unit_ts() == std::vector<uint32_t>({100, 200, 300}));
  CHECK(p.units[1].second == std::vector<Bytes>({{11}, {12}, {13}}));
}

TEST(grouper_drops_an_unrepaired_unit_and_resumes) {
  GrouperProbe p;
  p.add(100, 10, true);
  p.add(200, 11, false);
  p.add(200, 13, true);
  p.add(300, 14, true);
  p.g.evict(p.t0 + 80ms);
  CHECK(p.dropped == std::vector<uint32_t>({200}));
  CHECK(p.unit_ts() == std::vector<uint32_t>({100, 300}));
  p.add(200, 12, false, 90ms);  // 遅すぎるので無視
  CHECK(p.unit_ts().size() == 2 && p.g.pending() == 0);
}

TEST(grouper_loss_before_the_first_packet) {
  GrouperProbe p;
  p.add(100, 10, true);
  p.add(200, 12, true);  // 11（1グループ全体か、このグループの先頭）が欠けている
  CHECK(p.unit_ts() == std::vector<uint32_t>({100}));
  p.g.evict(p.t0 + 80ms);
  CHECK(p.dropped == std::vector<uint32_t>({200}));
  p.add(300, 13, true, 81ms);
  CHECK(p.unit_ts() == std::vector<uint32_t>({100, 300}));
}

// パケット数が書いてあれば（AppleのHEVCヘッダ拡張）、欠けたユニットの次は
// すぐにそろう。パケットが足りないユニットはまだ待つ。
TEST(grouper_stated_packet_count) {
  GrouperProbe p;
  p.g.add(7, 100, 10, true, Bytes{10}, p.t0, 1);
  p.g.add(7, 300, 12, false, Bytes{12}, p.t0, 2);  // 200（seq 11）は丸ごと欠ける
  p.g.add(7, 300, 13, true, Bytes{13}, p.t0, 2);
  CHECK(p.unit_ts() == std::vector<uint32_t>({100, 300}));
  p.g.add(7, 400, 14, false, Bytes{14}, p.t0, 3);
  p.g.add(7, 400, 16, true, Bytes{16}, p.t0, 3);  // 15が欠けている
  CHECK(p.unit_ts().size() == 2 && p.g.pending_ts(400));
  p.g.evict(p.t0 + 80ms);
  CHECK(p.dropped == std::vector<uint32_t>({400}));
}

TEST(grouper_sequence_wrap) {
  GrouperProbe p;
  p.add(100, 65533, true);
  p.add(200, 0, false);
  p.add(200, 65534, false);
  p.add(200, 1, true);
  p.add(200, 65535, false);
  CHECK(p.unit_ts() == std::vector<uint32_t>({100, 200}));
  CHECK(p.units.size() == 2 && p.units[1].second == std::vector<Bytes>({{0xFE}, {0xFF}, {0x00}, {0x01}}));
}

TEST(grouper_duplicates_and_marker_timeout) {
  GrouperProbe p;
  p.add(100, 10, false);
  p.add(100, 10, false);
  p.add(100, 11, true);
  p.add(100, 11, true);  // 送り出し済みユニットの遅れた重複
  CHECK(p.units.size() == 1 && p.units[0].second.size() == 2);
  p.add(200, 12, false);  // markerが来ない
  p.g.evict(p.t0 + 150ms);
  CHECK(p.dropped.empty());
  p.g.evict(p.t0 + 250ms);
  CHECK(p.dropped == std::vector<uint32_t>({200}));
}

// ── PictureAssembler ─────────────────────────────────────────────────────

struct AssemblerProbe {
  session::PictureAssembler a{4, 8ms};
  session::PictureAssembler::Clock::time_point t0 = session::PictureAssembler::Clock::now();

  static media::VideoFrame strip(int tile, uint32_t ts) {
    media::VideoFrame f;
    f.tile = tile;
    f.rtp_ts = ts;
    return f;
  }
  static std::vector<std::pair<int, uint32_t>> ids(const std::vector<media::VideoFrame>& v) {
    std::vector<std::pair<int, uint32_t>> out;
    for (const auto& f : v) out.push_back({f.tile, f.rtp_ts});
    return out;
  }
  std::vector<std::pair<int, uint32_t>> add(int tile, uint32_t ts, std::chrono::milliseconds at) {
    return ids(a.add(strip(tile, ts), t0 + at));
  }
};

using StripIds = std::vector<std::pair<int, uint32_t>>;

TEST(assembler_hands_over_a_picture_at_its_last_strip) {
  AssemblerProbe p;
  CHECK(p.add(0, 100, 0ms).empty());
  CHECK(p.add(1, 100, 5ms).empty());
  CHECK(p.ids(p.a.poll(p.t0 + 12ms)).empty());  // 期限より前に次のストリップが来るはず
  CHECK(p.add(2, 100, 10ms).empty());
  CHECK(p.add(3, 100, 15ms) == StripIds({{0, 100}, {1, 100}, {2, 100}, {3, 100}}));
  CHECK(p.a.empty());
}

TEST(assembler_without_the_last_strip_waits_for_the_deadline) {
  AssemblerProbe p;
  CHECK(p.add(1, 100, 0ms).empty());
  CHECK(p.add(2, 100, 5ms).empty());
  CHECK(p.ids(p.a.poll(p.t0 + 12ms)).empty());
  CHECK(p.ids(p.a.poll(p.t0 + 13ms)) == StripIds({{1, 100}, {2, 100}}));
  CHECK(p.ids(p.a.poll(p.t0 + 30ms)).empty());
}

TEST(assembler_packets_of_the_picture_extend_its_deadline) {
  AssemblerProbe p;
  CHECK(p.add(0, 100, 0ms).empty());
  CHECK(p.ids(p.a.packet(100, p.t0 + 6ms, false)).empty());  // 次のストリップが届き始める
  CHECK(p.ids(p.a.poll(p.t0 + 10ms)).empty());
  CHECK(p.ids(p.a.poll(p.t0 + 14ms)) == StripIds({{0, 100}}));
}

TEST(assembler_a_later_picture_hands_over_the_current_one) {
  AssemblerProbe p;
  CHECK(p.add(0, 100, 0ms).empty());
  CHECK(p.ids(p.a.packet(90, p.t0 + 1ms, false)).empty());   // 古いピクチャの遅れたパケット
  CHECK(p.ids(p.a.packet(200, p.t0 + 2ms, true)).empty());   // 100のストリップがまだ届いている途中
  CHECK(p.ids(p.a.packet(200, p.t0 + 3ms, false)) == StripIds({{0, 100}}));
  // 新しいピクチャのストリップを復号したら、先に前のピクチャを渡す。
  CHECK(p.add(1, 200, 4ms).empty());
  CHECK(p.add(0, 300, 5ms) == StripIds({{1, 200}}));
  CHECK(p.a.ts() == 300);
}

TEST(assembler_one_strip_streams_pass_straight_through) {
  session::PictureAssembler a{1, 8ms};
  media::VideoFrame f;
  f.rtp_ts = 7;
  CHECK(a.add(std::move(f), session::PictureAssembler::Clock::now()).size() == 1);
  CHECK(a.empty());
}

TEST(split_pictures_counts_pictures_shown_over_several_presents) {
  SplitPictures s;
  s.strip(100, 1);
  s.strip(100, 1);  // 2本のストリップを1回のPresentで
  s.strip(200, 2);
  s.strip(200, 3);
  s.strip(200, 4);  // 3本目のストリップでも、分かれたピクチャは1枚のまま
  s.strip(300, 5);  // ストリップ1本だけ
  using Counts = std::pair<uint64_t, uint64_t>;  // (分かれたピクチャ, 2本以上のストリップ)
  CHECK(s.take() == Counts(1, 2));
  CHECK(s.take() == Counts(0, 0));
}

// ── 制御チャネルのFramebufferUpdate（カーソル、レイアウト） ───────────────────

TEST(zlib_sync_flushed_stream) {
  const Bytes z = H(kCursorZ);
  const auto raw = zlib::decompress_sync_flushed(z.data(), z.size());
  CHECK(raw && *raw == H(kCursorRaw));
  CHECK(!zlib::decompress(z).has_value());  // 最終ブロックもトレーラーもなく、厳密なinflaterは拒む
  const Bytes regular = zlib::compress_stored(H(kCursorRaw));  // 完全なストリームも受け付ける
  const auto again = zlib::decompress_sync_flushed(regular.data(), regular.size());
  CHECK(again && *again == H(kCursorRaw));
  CHECK(!zlib::decompress_sync_flushed(z.data(), z.size() - 3).has_value());  // flushの途中で切れている
}

Bytes rect_header(uint16_t a, uint16_t b, uint16_t c, uint16_t d, int32_t enc) {
  return ByteWriter().be16(a).be16(b).be16(c).be16(d).be32(static_cast<uint32_t>(enc)).take();
}

// ディスプレイ1つ。スケール後1512x982、backing 3024x1964。
Bytes layout_payload() {
  ByteWriter w;
  w.be16(1).be16(1512).be16(982).be16(3024).be16(1964).be32(0xFFFFFFFF).be32(0).be16(1);
  Bytes entry(56, 0);
  wr_be32(&entry[16], 7);  // ディスプレイID
  wr_be16(&entry[28], 0);
  wr_be16(&entry[30], 0);
  wr_be16(&entry[32], 1964);  // y1
  wr_be16(&entry[34], 3024);  // x1
  return w.bytes(entry).take();
}

TEST(fbu_cursor_and_layout) {
  const int w = static_cast<int>(kCursorW), h = static_cast<int>(kCursorH);
  const Bytes z = H(kCursorZ), raw = H(kCursorRaw), layout = layout_payload();
  ByteWriter m;
  m.u8(0).u8(0).be16(6);
  m.bytes(rect_header(0, 0, 0, 0, 1010)).be16(3).bytes(H("aabbcc"));                            // 読み飛ばす
  m.bytes(rect_header(2, 1, static_cast<uint16_t>(w), static_cast<uint16_t>(h), 1104)).be32(40).be32(static_cast<uint32_t>(z.size())).bytes(z);
  m.bytes(rect_header(0, 0, 0, 0, 1104)).be32(40).be32(0);                                       // キャッシュにある
  m.bytes(rect_header(0, 0, 0, 0, 1104)).be32(99).be32(0);                                       // 一度も送っていない
  m.bytes(rect_header(0, 0, 0, 0, 0x451)).be16(static_cast<uint16_t>(layout.size())).bytes(layout);
  m.bytes(rect_header(0, 0, 0, 0, 7)).bytes(H("ffff"));                                          // 未知なのでここで読み終わる
  session::CursorCache cache;
  const session::FbuEvents ev = session::parse_fbu(m.take(), cache);

  CHECK(ev.cursors.size() == 3);
  if (ev.cursors.size() == 3) {
    const auto& c = ev.cursors[0];
    CHECK(c && c->width == w && c->height == h && c->hot_x == 2 && c->hot_y == 1);
    if (c) {
      Bytes want(raw.begin(), raw.begin() + w * h * 4);
      for (int p = 0; p < w * h; ++p) want[p * 4 + 3] = raw[w * h * 4 + p];  // アルファはマスクから
      CHECK(c->bgra == want);
    }
    CHECK(ev.cursors[1] == ev.cursors[0]);  // キャッシュした形
    CHECK(ev.cursors[2] == nullptr);        // 未知のid → 既定の矢印
  }
  CHECK(ev.layout.has_value());
  if (ev.layout) {
    CHECK(ev.layout->scaled_w == 1512 && ev.layout->scaled_h == 982);
    CHECK(ev.layout->backing_w == 3024 && ev.layout->backing_h == 1964 && ev.layout->displays == 1);
  }
  CHECK(ev.truncated);
  CHECK(cache.get(40) == ev.cursors[0] && !cache.get(99));

  // 矩形の途中で切れても、それまでに読んだ分は残る。
  Bytes cut = ByteWriter().u8(0).u8(0).be16(2).bytes(rect_header(0, 0, 0, 0, 1104)).be32(40).be32(0)
                  .bytes(rect_header(0, 0, 0, 0, 1104)).be32(41).take();
  const auto ev2 = session::parse_fbu(cut, cache);
  CHECK(ev2.cursors.size() == 1 && ev2.truncated);
}

// ── ループバックのホスト相手のセッション全体 ────────────────────────────────

struct Clip {
  Bytes sps, pps;
  std::vector<std::vector<Bytes>> aus;  // フレームごとのスライスNAL
  std::vector<bool> key;
};

Clip load_h264_clip() {
  Clip c;
  for (Bytes& nal : media::split_annexb(read_file(std::string(ISS_TEST_DATA_DIR) + "/h264.h264"))) {
    if (nal.empty()) continue;
    const int t = media::avc_nal_type(nal[0]);
    if (t == media::AVC_NAL_SPS && c.sps.empty()) c.sps = nal;
    if (t == media::AVC_NAL_PPS && c.pps.empty()) c.pps = nal;
    if (t != media::AVC_NAL_SLICE_NONIDR && t != media::AVC_NAL_SLICE_IDR) continue;
    const Bytes rbsp = media::remove_emulation_prevention(nal.data() + 1, nal.size() - 1);
    media::BitReader br(rbsp);
    if (br.read_ue() == 0 || c.aus.empty()) {  // first_mb_in_slice == 0なら新しいピクチャ
      c.aus.emplace_back();
      c.key.push_back(false);
    }
    c.key.back() = c.key.back() || media::avc_nal_is_keyframe(nal);
    c.aus.back().push_back(std::move(nal));
  }
  return c;
}

// Appleが帯域外で送るH.264の設定。0x92、avc1のsample entry、そのavcCの順。
Bytes apple_avc_config(const Bytes& sps, const Bytes& pps) {
  return ByteWriter()
      .u8(0x92)
      .str("avc1")
      .zeros(8)
      .str("avcC")
      .u8(1).u8(sps[1]).u8(sps[2]).u8(sps[3]).u8(0xFF).u8(0xE1)
      .be16(static_cast<uint16_t>(sps.size())).bytes(sps)
      .u8(1)
      .be16(static_cast<uint16_t>(pps.size())).bytes(pps)
      .take();
}

// 1つのNALに対するRFC 6184のペイロード。single NAL unitか、FU-Aの断片。
std::vector<Bytes> rtp_payloads(const Bytes& nal) {
  constexpr size_t kMax = 1100, kFrag = 1000;
  if (nal.size() <= kMax) return {nal};
  std::vector<Bytes> out;
  for (size_t off = 1; off < nal.size(); off += kFrag) {
    const size_t end = std::min(nal.size(), off + kFrag);
    uint8_t fu_header = nal[0] & 0x1F;
    if (off == 1) fu_header |= 0x80;
    if (end == nal.size()) fu_header |= 0x40;
    out.push_back(ByteWriter().u8((nal[0] & 0xE0) | 28).u8(fu_header).bytes(Bytes(nal.begin() + off, nal.begin() + end)).take());
  }
  return out;
}

TEST(session_streams_h264_from_a_loopback_host) {
  const Clip clip = load_h264_clip();
  CHECK(clip.aus.size() == 30 && !clip.sps.empty() && !clip.pps.empty());
  if (clip.aus.size() != 30) return;

  // 2つ目のキーフレームのあと、複数パケットからなる最初のPフレームの途中で
  // 1パケットを落とす。デコードは次のキーフレームから再開しなければならない。
  size_t lost_au = 0;
  for (size_t i = 11; i < clip.aus.size() && !lost_au; ++i) {
    size_t n = 0;
    for (const Bytes& nal : clip.aus[i]) n += rtp_payloads(nal).size();
    if (!clip.key[i] && n >= 2) lost_au = i;
  }
  size_t next_key = lost_au + 1;
  while (next_key < clip.aus.size() && !clip.key[next_key]) ++next_key;
  CHECK(lost_au && next_key < clip.aus.size());
  const uint64_t expected_frames = lost_au + (clip.aus.size() - next_key);

  const rfb::VirtualDisplayParams display;
  NegotiationServerResult res;
  std::atomic<int> udp_packets{0};
  LoopbackServer server([&](SOCKET s) {
    negotiation_server(s, res, "", &display);
    // クライアントが送った0x1cに、ホスト→ビューアの映像の鍵が入っている。
    const Bytes& m = res.msg_1c;
    const size_t vo = 0x80 + rd_be16(&m[10]);
    proto::SrtpEncryptor enc(slice(m, vo + 0x2e, 46), 0x1000);
    net::UdpSocket udp = net::UdpSocket::bind(0);
    sockaddr_in local{};
    int len = sizeof(local);
    getsockname(s, reinterpret_cast<sockaddr*>(&local), &len);
    const uint16_t video_port = static_cast<uint16_t>(ntohs(local.sin_port) + 1);
    uint16_t seq = 1000;
    auto send = [&](uint32_t ts, bool marker, const Bytes& payload, bool lose = false) {
      const Bytes pkt = enc.encrypt_rtp(seq++, 0, ts, marker, 96, payload);
      if (!lose) udp.send_to("127.0.0.1", video_port, pkt);
      ++udp_packets;
    };
    send(1, true, apple_avc_config(clip.sps, clip.pps));
    for (size_t i = 0; i < clip.aus.size(); ++i) {
      std::vector<Bytes> payloads;
      for (const Bytes& nal : clip.aus[i]) {
        for (Bytes& p : rtp_payloads(nal)) payloads.push_back(std::move(p));
      }
      for (size_t j = 0; j < payloads.size(); ++j) {
        send(static_cast<uint32_t>(3000 * (i + 1)), j + 1 == payloads.size(), payloads[j], i == lost_au && j == 1);
      }
    }
    char b;
    while (::recv(s, &b, 1, 0) > 0) {
    }  // クライアントが切るまで制御接続を保つ
  });

  const proto::ConnectOptions fast = loopback_connect_options(server.port());
  session::SessionOptions opt;
  opt.host = "127.0.0.1";
  opt.port = server.port();
  opt.username = fast.username;
  opt.password = fast.password;
  opt.display = display;
  opt.prefer_hwaccel = false;
  opt.warmup = false;
  opt.timing = fast.timing;
  session::Session sess(opt);
  bool connected = false;
  try {
    sess.connect();
    connected = true;
  } catch (const std::exception& e) {
    std::fprintf(stderr, "    connect: %s\n", e.what());
  }
  CHECK(connected);
  session::SessionStats st;
  std::vector<media::VideoFrame> frames;
  for (int i = 0; connected && i < 100; ++i) {
    for (auto& f : sess.take_frames()) frames.push_back(std::move(f));
    st = sess.stats();
    if (st.frames_decoded >= expected_frames && st.dropped_frames) break;
    std::this_thread::sleep_for(50ms);
  }
  sess.stop();
  const std::string err = server.join();
  CHECK(err.empty());
  if (!err.empty()) std::fprintf(stderr, "    server: %s\n", err.c_str());
  if (!connected) return;

  CHECK(sess.canvas_width() == 3840 && sess.canvas_height() == 2160);  // 0x1cの答えから
  CHECK(st.frames_decoded == expected_frames);
  if (st.frames_decoded != expected_frames) {
    std::fprintf(stderr, "    decoded %llu, expected %llu (lost AU %zu, next key %zu)\n",
                 static_cast<unsigned long long>(st.frames_decoded), static_cast<unsigned long long>(expected_frames),
                 lost_au, next_key);
  }
  CHECK(st.dropped_frames == 1);
  CHECK(st.lost_packets == 1);
  CHECK(st.nacks_sent >= 1);
  CHECK(st.keyframe_requests >= 1);
  CHECK(st.video_packets == static_cast<uint64_t>(udp_packets) - 1);
  CHECK(!frames.empty() && frames.back().width == 640 && frames.back().height == 360);
  CHECK(st.decoder == "software");
}

// 同じことをIPv6（::1）で確かめる。制御接続もメディアも。
TEST(session_streams_over_ipv6) {
  const Clip clip = load_h264_clip();
  CHECK(clip.aus.size() == 30);
  if (clip.aus.size() != 30) return;
  const rfb::VirtualDisplayParams display;
  NegotiationServerResult res;
  std::atomic<uint16_t> video_port{0};
  LoopbackServer server(
      std::vector<ServerScript>{[&](SOCKET s) {
        negotiation_server(s, res, "", &display);
        const Bytes& m = res.msg_1c;
        proto::SrtpEncryptor enc(slice(m, 0x80 + rd_be16(&m[10]) + 0x2e, 46), 0x1000);
        net::UdpSocket udp = net::UdpSocket::bind(0);
        uint16_t seq = 1;
        auto send = [&](uint32_t ts, bool marker, const Bytes& payload) {
          if (!udp.send_to("::1", video_port, enc.encrypt_rtp(seq++, 0, ts, marker, 96, payload))) {
            throw std::runtime_error("UDP send to ::1 failed");
          }
        };
        send(1, true, apple_avc_config(clip.sps, clip.pps));
        for (size_t i = 0; i < clip.aus.size(); ++i) {
          std::vector<Bytes> payloads;
          for (const Bytes& nal : clip.aus[i]) {
            for (Bytes& p : rtp_payloads(nal)) payloads.push_back(std::move(p));
          }
          for (size_t j = 0; j < payloads.size(); ++j) {
            send(static_cast<uint32_t>(3000 * (i + 1)), j + 1 == payloads.size(), payloads[j]);
          }
        }
        char b;
        while (::recv(s, &b, 1, 0) > 0) {
        }
      }},
      AF_INET6);
  video_port = static_cast<uint16_t>(server.port() + 1);

  const proto::ConnectOptions fast = loopback_connect_options(server.port());
  session::SessionOptions opt;
  opt.host = "::1";
  opt.port = server.port();
  opt.username = fast.username;
  opt.password = fast.password;
  opt.display = display;
  opt.prefer_hwaccel = false;
  opt.warmup = false;
  opt.timing = fast.timing;
  session::Session sess(opt);
  bool connected = false;
  try {
    sess.connect();
    connected = true;
  } catch (const std::exception& e) {
    std::fprintf(stderr, "    connect: %s\n", e.what());
  }
  CHECK(connected);
  session::SessionStats st;
  for (int i = 0; connected && i < 100 && st.frames_decoded < clip.aus.size(); ++i) {
    sess.take_frames();
    st = sess.stats();
    std::this_thread::sleep_for(50ms);
  }
  sess.stop();
  const std::string err = server.join();
  CHECK(err.empty());
  if (!err.empty()) std::fprintf(stderr, "    server: %s\n", err.c_str());
  CHECK(st.frames_decoded == clip.aus.size());
  CHECK(st.lost_packets == 0);
}

// 指定したbackingサイズ（2倍）のディスプレイ1つを持つAppleDisplayLayoutのFBU。
Bytes layout_fbu(uint16_t backing_w, uint16_t backing_h) {
  ByteWriter w;
  w.be16(1).be16(backing_w / 2).be16(backing_h / 2).be16(backing_w).be16(backing_h).be32(0xFFFFFFFF).be32(0).be16(1);
  Bytes entry(56, 0);
  wr_be16(&entry[32], backing_h);
  wr_be16(&entry[34], backing_w);
  const Bytes payload = w.bytes(entry).take();
  return ByteWriter().u8(0).u8(0).be16(1).bytes(rect_header(0, 0, 0, 0, 0x451))
      .be16(static_cast<uint16_t>(payload.size())).bytes(payload).take();
}

TEST(session_resize_reoffers_the_media_stream) {
  const Clip clip = load_h264_clip();
  CHECK(!clip.aus.empty());
  if (clip.aus.empty()) return;
  const rfb::VirtualDisplayParams display;
  NegotiationServerResult res;
  rfb::VirtualDisplayParams asked;
  std::atomic<bool> got_resize{false}, got_reoffer{false};
  LoopbackServer server([&](SOCKET s) {
    negotiation_server(s, res, "", &display);
    // connect()に足りるだけの映像。設定とキーフレーム1つ。
    const Bytes& m = res.msg_1c;
    proto::SrtpEncryptor enc(slice(m, 0x80 + rd_be16(&m[10]) + 0x2e, 46), 0x3000);
    net::UdpSocket udp = net::UdpSocket::bind(0);
    sockaddr_in local{};
    int len = sizeof(local);
    getsockname(s, reinterpret_cast<sockaddr*>(&local), &len);
    const uint16_t video_port = static_cast<uint16_t>(ntohs(local.sin_port) + 1);
    uint16_t seq = 1;
    udp.send_to("127.0.0.1", video_port, enc.encrypt_rtp(seq++, 0, 1, true, 96, apple_avc_config(clip.sps, clip.pps)));
    std::vector<Bytes> payloads;
    for (const Bytes& nal : clip.aus[0]) {
      for (Bytes& p : rtp_payloads(nal)) payloads.push_back(std::move(p));
    }
    for (size_t j = 0; j < payloads.size(); ++j) {
      udp.send_to("127.0.0.1", video_port, enc.encrypt_rtp(seq++, 0, 3000, j + 1 == payloads.size(), 96, payloads[j]));
    }
    srv_send(s, res.cipher->encrypt_message(layout_fbu(1920, 1080)));  // 最初のレイアウト
    // クライアントのレコードを読む。0x1dを待って新しいレイアウトで答え、
    // そのあと0x1cの出し直しを待つ。
    const auto deadline = std::chrono::steady_clock::now() + 8s;
    while (std::chrono::steady_clock::now() < deadline && !got_reoffer) {
      const Bytes ct = srv_recv(s, rd_be16(srv_recv(s, 2).data()));
      auto msg = res.cipher->decrypt_message(ct.data(), ct.size());
      expect(msg.has_value(), "client record authenticates");
      if (msg->empty()) continue;
      if ((*msg)[0] == rfb::CLI_VIRTUAL_DISPLAY && !got_resize) {
        // ポイント値は最初のモード項目にある。12バイトのヘッダのあとにディスプレイ
        // 情報が続き、そのモードは+0x9Cから始まる（ピクセル、次にポイント）。
        asked.width = static_cast<int>(rd_be32(&(*msg)[12 + 0x9C + 8]));
        asked.height = static_cast<int>(rd_be32(&(*msg)[12 + 0x9C + 12]));
        got_resize = true;
        srv_send(s, res.cipher->encrypt_message(layout_fbu(2880, 1800)));
      } else if ((*msg)[0] == rfb::CLI_MEDIA_NEGOTIATION && got_resize) {
        got_reoffer = true;
      }
    }
    char b;
    while (::recv(s, &b, 1, 0) > 0) {
    }
  });

  const proto::ConnectOptions fast = loopback_connect_options(server.port());
  session::SessionOptions opt;
  opt.host = "127.0.0.1";
  opt.port = server.port();
  opt.username = fast.username;
  opt.password = fast.password;
  opt.display = display;
  opt.prefer_hwaccel = false;
  opt.warmup = false;
  opt.timing = fast.timing;
  session::Session sess(opt);
  bool connected = false;
  try {
    sess.connect();
    connected = true;
  } catch (const std::exception& e) {
    std::fprintf(stderr, "    connect: %s\n", e.what());
  }
  if (connected) {
    std::this_thread::sleep_for(300ms);  // 最初のレイアウトが届くのを待つ
    rfb::VirtualDisplayParams want;
    want.width = 1440;
    want.height = 900;
    want.hidpi_scale = 2.0;
    sess.request_resolution(want);
    for (int i = 0; i < 100 && !got_reoffer; ++i) std::this_thread::sleep_for(50ms);
    CHECK(got_resize && got_reoffer);
    CHECK(asked.width == 1440 && asked.height == 900);
    CHECK(sess.canvas_width() == 2880 && sess.canvas_height() == 1800);
  }
  sess.stop();
  server.join();
  CHECK(connected);
}

}  // namespace

// iss-tests.exe --fake-host [SECONDS]。本物のiss-win.exeを動かすための
// ループバックの「Mac」。warmupのTCPとセッション1つ（テスト用の認証情報）を受け、
// H.264のテストクリップを30 fpsで繰り返し流す。クライアントが切るかSECONDSが
// 過ぎるまで続ける。ポートと認証情報を表示する。
int run_fake_host(int seconds) {
  const Clip clip = load_h264_clip();
  if (clip.aus.empty()) {
    std::fprintf(stderr, "no test clip\n");
    return 1;
  }
  std::atomic<bool> done{false};
  NegotiationServerResult res;
  auto warmup = [](SOCKET s) {
    srv_send(s, rfb_version());
    srv_recv(s, 12);
    srv_send(s, H("0121"));
    char b;
    while (::recv(s, &b, 1, 0) > 0) {
    }
  };
  auto host = [&](SOCKET s) {
    struct Done {
      std::atomic<bool>& d;
      ~Done() { d = true; }
    } mark{done};
    negotiation_server(s, res, "", nullptr);
    const Bytes& m = res.msg_1c;
    proto::SrtpEncryptor enc(slice(m, 0x80 + rd_be16(&m[10]) + 0x2e, 46), 0x2000);
    net::UdpSocket udp = net::UdpSocket::bind(0);
    sockaddr_in local{};
    int len = sizeof(local);
    getsockname(s, reinterpret_cast<sockaddr*>(&local), &len);
    const uint16_t video_port = static_cast<uint16_t>(ntohs(local.sin_port) + 1);
    // ビューアの入力は制御チャネルに届く。それを読み捨て、
    // ビューアが切ったら止める。
    auto client_gone = [&] {
      fd_set rd;
      FD_ZERO(&rd);
      FD_SET(s, &rd);
      timeval tv{0, 0};
      if (select(0, &rd, nullptr, nullptr, &tv) != 1) return false;
      char buf[4096];
      return ::recv(s, buf, sizeof(buf), 0) <= 0;
    };
    uint16_t seq = 1;
    auto send = [&](uint32_t ts, bool marker, const Bytes& payload) {
      udp.send_to("127.0.0.1", video_port, enc.encrypt_rtp(seq++, 0, ts, marker, 96, payload));
    };
    send(1, true, apple_avc_config(clip.sps, clip.pps));
    // 32x32のカーソル（白い縁の赤い四角で、角が透明。ホットスポットは4,4）を、
    // Macが形を送るのと同じくenc 1104で送る。
    {
      constexpr int kW = 32, kH = 32;
      Bytes raw(kW * kH * 5, 0);
      for (int y = 0; y < kH; ++y) {
        for (int x = 0; x < kW; ++x) {
          uint8_t* p = &raw[(y * kW + x) * 4];
          const bool edge = x < 2 || y < 2 || x >= kW - 2 || y >= kH - 2;
          p[0] = edge ? 255 : 0;  // B
          p[1] = edge ? 255 : 0;  // G
          p[2] = 255;             // R
          raw[kW * kH * 4 + y * kW + x] = static_cast<uint8_t>(x + y < 12 ? 0 : 255);  // マスク。角を透明にする
        }
      }
      const Bytes z = zlib::compress_stored(raw);
      const Bytes fbu = ByteWriter().u8(0).u8(0).be16(1).be16(4).be16(4).be16(kW).be16(kH).be32(1104)
                            .be32(500).be32(static_cast<uint32_t>(z.size())).bytes(z).take();
      srv_send(s, res.cipher->encrypt_message(fbu));
    }
    const auto start = std::chrono::steady_clock::now();
    for (uint32_t n = 0; std::chrono::steady_clock::now() - start < std::chrono::seconds(seconds) && !client_gone(); ++n) {
      std::vector<Bytes> payloads;
      for (const Bytes& nal : clip.aus[n % clip.aus.size()]) {
        for (Bytes& p : rtp_payloads(nal)) payloads.push_back(std::move(p));
      }
      // Macの映像クロックは24 kHz。33 msのフレームあたり800ティック。
      for (size_t j = 0; j < payloads.size(); ++j) send(800 * (n + 1), j + 1 == payloads.size(), payloads[j]);
      std::this_thread::sleep_until(start + std::chrono::milliseconds(33) * (n + 1));
    }
  };
  LoopbackServer server(std::vector<ServerScript>{warmup, host});
  std::printf("fake host on 127.0.0.1 port %u, user %s, password %s\n", server.port(), S(kSrpUsername).c_str(),
              S(kSrpPassword).c_str());
  std::fflush(stdout);
  const auto give_up = std::chrono::steady_clock::now() + std::chrono::seconds(seconds + 60);
  while (!done && std::chrono::steady_clock::now() < give_up) std::this_thread::sleep_for(100ms);
  const std::string err = server.join();
  std::printf("fake host done%s%s\n", err.empty() ? "" : ": ", err.c_str());
  return err.empty() ? 0 : 1;
}
