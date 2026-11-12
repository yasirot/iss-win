#include "session/session.h"

#include <windows.h>

#include <share.h>

#include <algorithm>
#include <cstdlib>
#include <format>
#include <stdexcept>

#include "core/log.h"
#include "crypto/crypto.h"
#include "media/nalu.h"
#include "proto/offers.h"
#include "proto/rfb.h"
#include "proto/rtcp.h"

namespace iss::session {
namespace {

using namespace std::chrono_literals;
using Clock = std::chrono::steady_clock;

constexpr int kBurstAttempts = 3;
constexpr auto kBurstRetrySleep = 800ms;
constexpr auto kBurstMax = 4s;            // H.264の開始時のまとまりを読み切る上限（session.py）
constexpr int kBurstQuietMs = 50;
constexpr size_t kBurstEnoughPackets = 400;
constexpr size_t kVideoQueueMax = 16384;
// HEVC: Macは1枚のピクチャの帯を約5.2 ms間隔で送る（LAN上の5Kで、ある帯の
// 最後のパケット → 次の帯の最初のパケットまで、最大6.5 ms）。この時間内に
// 次の帯が来なければピクチャはそろったとみなす（PictureAssembler）。
constexpr auto kTileGap = 8ms;
constexpr auto kQuickRepairWait = 15ms;
constexpr auto kTxInterval = 500ms;
constexpr int kSrEveryTicks = 10;         // 5秒
constexpr int kStatsEveryTicks = 10;
constexpr auto kKeyframeRequestInterval = 500ms;
constexpr auto kHevcRefreshRetry = 150ms;
// H.264のIDRは要求を送ってから70-100 ms後に届く（LAN、4K）。Macが送るIDRは
// 多くても1秒に1回ほど。
constexpr int64_t kAvcAnswerMs = 120;
// HEVC: IDRの受信中（その損失に気づいた時点）に送った要求は無視され、150 ms後の
// 再要求にだけ応答があった。IDRの最初のパケットから9 ms後に送った要求には
// すぐ応答があった（2026-10-10に計測）。
constexpr int64_t kAfterIdrMs = 12;
constexpr int64_t kIdleMs = 1500;         // この間ビデオが来なければエンコーダは休止中。要求しない
constexpr int64_t kStallMs = 3000;        // パケットはあるがこの間ピクチャがない: キーフレームを要求
constexpr auto kAdoptStall = 2s;
// 接続直後（0x1cの問い合わせや再問い合わせのたびに別のストリームが始まることがあり、
// ホストは最後の1本だけを残す）とリサイズの後は、自分のSSRCが途切れたらすぐ
// 新しいSSRCに乗り換える。
constexpr auto kAdoptStallEarly = 300ms;
constexpr int64_t kFastAdoptWindowMs = 10000;
constexpr auto kAdoptCooldown = 1500ms;
constexpr uint64_t kAdoptMinPackets = 5;
constexpr size_t kUnknownSsrcBuffer = 4000;  // グループ外のSSRCごとに保持するパケット数（数秒分）
// AppleのH.264のpicture order countは13ビット（8192で一周する）で、D3D11VAは
// その折り返しをまたぐと何のエラーも出さずに画を壊す。その十分手前で新しい
// イントラを要求する。デコーダを止めたり作り直したりはしない（session.py、
// _maybe_reanchor_d3d11va_avc）。
constexpr uint64_t kD3d11ReanchorFrames = 7000;
constexpr auto kReanchorMinInterval = 3s;
constexpr uint8_t kAudioPt = 101;
constexpr int32_t kEncCursorRect = 1104;
constexpr uint8_t kMsgMiscStatus = 0x14;
// 約2.1秒ごとのハートビート。RFCではcmd 12、実機のMacからはcmd 4が来る。
constexpr uint16_t kMiscHeartbeat = 12, kMiscHeartbeatAlt = 4;
// Macの音声は無音でも約100パケット/秒流れる。RTCPだけだと数秒おきにしか来ない。
// どちらもこの時間来なければMac側のメディアセッションが終わっている（ディスプレイの
// スリープ後のロック画面でそうなる）ので、提示し直す。
constexpr int64_t kMediaSilentMs = 3000;
constexpr int64_t kMediaSilentNoAudioMs = 12000;
constexpr int64_t kReofferBackoffMinMs = 5000, kReofferBackoffMaxMs = 60000;
const Bytes kHeartbeatPayload = {0x00, 0x68, 0x34, 0x00};
const Bytes kStartCode = {0, 0, 0, 1};

int64_t now_ms() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now().time_since_epoch()).count();
}

double unix_now() {
  FILETIME ft;
  GetSystemTimePreciseAsFileTime(&ft);
  const uint64_t t = (uint64_t(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;  // 1601年からの100 ns単位
  return double(t - 116444736000000000ull) / 1e7;
}

bool env_set(const char* name) { return GetEnvironmentVariableA(name, nullptr, 0) > 0; }

// 連番のSSRCが1つの画質の層をなし、タイルごとにSSRCが1つある。パケットが
// 最も多い層をデコードする（SRTPDecryptor.get_primary_ssrc_group）。
std::map<uint32_t, int> primary_ssrc_group(const std::map<uint32_t, uint64_t>& counts, int tiles) {
  std::vector<std::vector<uint32_t>> groups;
  for (const auto& [ssrc, n] : counts) {
    if (!groups.empty() && ssrc - groups.back().back() <= 1 && static_cast<int>(groups.back().size()) < tiles) {
      groups.back().push_back(ssrc);
    } else {
      groups.push_back({ssrc});
    }
  }
  const std::vector<uint32_t>* best = nullptr;
  uint64_t best_n = 0;
  for (const auto& g : groups) {
    uint64_t n = 0;
    for (uint32_t s : g) n += counts.at(s);
    if (!best || n > best_n) {
      best = &g;
      best_n = n;
    }
  }
  std::map<uint32_t, int> out;
  if (best) {
    for (size_t i = 0; i < best->size(); ++i) out[(*best)[i]] = static_cast<int>(i);
  }
  return out;
}

// Appleはストリームの各タイルのSSRCを、タイル0（キーフレームも運ぶ最上段の帯）の
// ものから連番で振る。帯に変化がないタイルはまだ何も送っていないことがあるので、
// グループは最小のSSRCから数えて補う。
std::map<uint32_t, int> complete_tiles(std::map<uint32_t, int> map, int tiles) {
  if (tiles <= 1 || map.empty()) return map;
  const uint32_t base = map.begin()->first;
  map.clear();
  for (int i = 0; i < tiles; ++i) map[base + static_cast<uint32_t>(i)] = i;
  return map;
}

std::string ssrc_list(const std::map<uint32_t, int>& m) {
  std::string s;
  for (const auto& [ssrc, tile] : m) s += std::format("{}0x{:08x}", s.empty() ? "" : " ", ssrc);
  return s;
}

// まとまりの中のピクチャ: (ssrc, RTPタイムスタンプ) → シーケンス番号順のペイロード。
std::map<std::pair<uint32_t, uint32_t>, std::vector<Bytes>> burst_units(const std::vector<proto::RtpPacket>& burst) {
  std::map<std::pair<uint32_t, uint32_t>, std::vector<const proto::RtpPacket*>> units;
  for (const proto::RtpPacket& p : burst) units[{p.ssrc, p.ts}].push_back(&p);
  std::map<std::pair<uint32_t, uint32_t>, std::vector<Bytes>> out;
  for (auto& [key, pkts] : units) {
    const uint16_t first = pkts.front()->seq;
    std::sort(pkts.begin(), pkts.end(), [first](const proto::RtpPacket* a, const proto::RtpPacket* b) {
      return static_cast<int16_t>(a->seq - first) < static_cast<int16_t>(b->seq - first);
    });
    auto& payloads = out[key];
    for (const proto::RtpPacket* p : pkts) payloads.push_back(p->payload);
  }
  return out;
}

bool hevc_is_param_set(int t) { return t >= media::HEVC_NAL_VPS && t <= media::HEVC_NAL_PPS; }

// VPS / SPS / PPSを単独で、またはaggregation packet（ヘッダ、DONL、サイズ付きの
// NALの並び）に入れて運ぶHEVCのRTPペイロードか。
bool hevc_payload_has_params(const Bytes& p) {
  if (p.size() < 2) return false;
  const int t = media::hevc_nal_type(p[0]);
  if (hevc_is_param_set(t)) return true;
  if (t != media::HEVC_NAL_AGGREGATION) return false;
  for (size_t pos = 4; pos + 3 <= p.size();) {
    const size_t size = rd_be16(&p[pos]);
    if (size == 0 || pos + 2 + size > p.size()) return false;
    if (hevc_is_param_set(media::hevc_nal_type(p[pos + 2]))) return true;
    pos += 2 + size;
  }
  return false;
}

// --hevc-probe: HEVCを提示したときにMacが開始時のまとまりで送ったもの。SSRCごとの
// パケット数と、各SSRCのSPSが示すピクチャのサイズ（画面がタイルに分かれていれば
// タイル1枚のサイズ）。
std::string hevc_probe_report(const std::vector<proto::RtpPacket>& burst, const proto::CanvasDims& canvas) {
  std::map<uint32_t, uint64_t> per_ssrc;
  size_t avc_config = 0;
  for (const proto::RtpPacket& p : burst) {
    ++per_ssrc[p.ssrc];
    if (!p.payload.empty() && p.payload[0] == media::APPLE_AVC_CONFIG_MARKER) ++avc_config;
  }
  const auto units = burst_units(burst);
  std::map<uint32_t, media::HevcSpsInfo> sps;
  for (const auto& [key, payloads] : units) {
    if (sps.count(key.first)) continue;
    for (const Bytes& nal : media::hevc_reassemble_group(payloads)) {
      if (auto info = media::parse_hevc_sps(nal)) {
        sps.emplace(key.first, *info);
        break;
      }
    }
  }
  std::string text = std::format("HEVC probe: the Mac's answer says {}x{} in {} tile(s); {} packets in 4 s",
                                 canvas.width, canvas.height, canvas.tiles, burst.size());
  for (const auto& [ssrc, n] : per_ssrc) {
    text += std::format("\n  SSRC 0x{:08x}: {} packets", ssrc, n);
    if (auto it = sps.find(ssrc); it != sps.end()) {
      const media::HevcSpsInfo& s = it->second;
      text += std::format(", SPS {}x{} {} level {}.{}", s.width, s.height,
                          s.chroma_format_idc == 3 ? "4:4:4" : s.chroma_format_idc == 1 ? "4:2:0" : "chroma ?",
                          s.level_idc / 30, s.level_idc % 30 / 3);
    }
  }
  if (avc_config) text += std::format("\n  {} H.264 config packet(s): the Mac answered in H.264", avc_config);
  if (burst.empty()) text += "\n  no video arrived";
  // デコーダを試せるよう、最も多いグループのSSRCごとにAnnex-Bファイルを書く。
  // 全SSRC分を、ピクチャが届き始めた順（共有の1つのデコーダに渡す順）に並べた
  // ファイルも書く。
  wchar_t tmp[MAX_PATH];
  if (GetTempPathW(MAX_PATH, tmp)) {
    const auto group = primary_ssrc_group(per_ssrc, 4);
    Bytes all;
    std::set<std::pair<uint32_t, uint32_t>> written;
    for (const proto::RtpPacket& p : burst) {
      if (!group.count(p.ssrc) || !written.insert({p.ssrc, p.ts}).second) continue;
      for (const Bytes& nal : media::hevc_reassemble_group(units.at({p.ssrc, p.ts}))) {
        all.insert(all.end(), kStartCode.begin(), kStartCode.end());
        all.insert(all.end(), nal.begin(), nal.end());
      }
    }
    if (FILE* f = nullptr; _wfopen_s(&f, std::format(L"{}iss-hevc-probe-all.h265", tmp).c_str(), L"wb") == 0 && f) {
      fwrite(all.data(), 1, all.size(), f);
      fclose(f);
    }
    for (const auto& [ssrc, tile] : group) {
      Bytes annexb;
      for (const auto& [key, payloads] : units) {
        if (key.first != ssrc) continue;
        for (const Bytes& nal : media::hevc_reassemble_group(payloads)) {
          annexb.insert(annexb.end(), kStartCode.begin(), kStartCode.end());
          annexb.insert(annexb.end(), nal.begin(), nal.end());
        }
      }
      const std::wstring path = std::format(L"{}iss-hevc-probe-tile{}.h265", tmp, tile);
      if (FILE* f = nullptr; _wfopen_s(&f, path.c_str(), L"wb") == 0 && f) {
        fwrite(annexb.data(), 1, annexb.size(), f);
        fclose(f);
      }
    }
    text += "\n  tiles written to %TEMP%\\iss-hevc-probe-tile*.h265";
  }
  log::info("{}", text);
  return text;
}

Bytes avc_extradata(const Bytes& sps, const Bytes& pps) {
  Bytes out = kStartCode;
  const Bytes patched = media::patch_avc_sps_dpb(sps);
  out.insert(out.end(), patched.begin(), patched.end());
  out.insert(out.end(), kStartCode.begin(), kStartCode.end());
  out.insert(out.end(), pps.begin(), pps.end());
  return out;
}

// AppleのHPクライアントはポインタイベントをすべてmsg 0x10
// （HandleEncryptedEventMessage）で送り、素の0x05 PointerEventは使わない。中身は
// 16バイトで、トグル後のCBC鍵を使ったAES-128-ECBで暗号化する。バイト10は0xff必須。
// ここではバイト2..5と6..9は0にする。Appleのクライアントは6..9にイベント時刻の
// 差分を書き、その書き込み関数はクリック数も引数に取る（ISS_POINTER）。
Bytes build_msg10_pointer(const Bytes& cbc_key, uint8_t buttons, int x, int y, uint32_t arg = 0,
                          uint32_t delta = 0) {
  Bytes plain(16, 0);
  wr_be32(&plain[2], arg);
  wr_be32(&plain[6], delta);
  plain[10] = 0xff;
  plain[11] = buttons;
  wr_be16(&plain[12], static_cast<uint16_t>(x));
  wr_be16(&plain[14], static_cast<uint16_t>(y));
  const Bytes ct = crypto::aes_ecb_encrypt(Bytes(cbc_key.begin(), cbc_key.begin() + 16), plain);
  Bytes out = {0x10, 0x00};
  out.insert(out.end(), ct.begin(), ct.end());
  return out;
}

}  // namespace

Session::Session(SessionOptions opt) : opt_(std::move(opt)) {
  char buf[16] = {};
  GetEnvironmentVariableA("ISS_POINTER", buf, sizeof(buf));
  const std::string mode = buf;
  if (mode == "rfb") pointer_mode_ = PointerMode::Rfb;
  if (mode == "time") pointer_mode_ = PointerMode::Time;
  if (mode == "clicks") pointer_mode_ = PointerMode::Clicks;
  if (pointer_mode_ != PointerMode::Msg10) log::info("ISS_POINTER={}: pointer events changed for the experiment", mode);
  pointer_t0_ms_ = now_ms();
  if (char ack[16] = {}; GetEnvironmentVariableA("ISS_LTR_ACK", ack, sizeof(ack))) {
    ltr_ack_ = std::string(ack) == "0" ? LtrAck::Off : std::string(ack) == "tile0" ? LtrAck::Tile0 : LtrAck::All;
  }
  if (char r[16] = {}; GetEnvironmentVariableA("ISS_REFRESH", r, sizeof(r))) {
    const std::string kind = r;
    refresh_pli_ = kind == "pli";
    refresh_fir_ = kind == "fir";
    refresh_legacy_ = kind == "legacy";
    log::info("ISS_REFRESH={}: only that refresh request is sent", kind);
  }
  if (char r[16] = {}; GetEnvironmentVariableA("ISS_REFRESH_TARGET", r, sizeof(r))) {
    refresh_all_ssrcs_ = std::string(r) == "all";
  }
  char loss[16] = {};
  if (GetEnvironmentVariableA("ISS_LOSS_PERMILLE", loss, sizeof(loss))) {
    loss_permille_ = static_cast<uint32_t>(std::clamp(std::atoi(loss), 0, 1000));
    log::info("ISS_LOSS_PERMILLE={}: that share of the main display's video packets is thrown away", loss_permille_);
  }
}

Session::~Session() { stop(); }

std::string Session::failure() const {
  std::lock_guard lk(info_mu_);
  return failure_;
}

void Session::fail(const std::string& why) {
  {
    std::lock_guard lk(info_mu_);
    if (failure_.empty()) failure_ = why;
  }
  if (alive_.exchange(false)) log::error("session ended: {}", why);
}

// ── 接続 ─────────────────────────────────────────────────────────────────

void Session::connect() {
  struct Wipe {
    std::string& s;
    ~Wipe() { secure_wipe(s); }
  } wipe{opt_.password};

  try {
    if (!opt_.dump_path.empty()) {
      dump_ = _wfsopen(opt_.dump_path.c_str(), L"wb", _SH_DENYWR);
      if (!dump_) log::warn("cannot write the record dump");
    }
    if (wchar_t path[MAX_PATH] = {}; opt_.media && GetEnvironmentVariableW(L"ISS_RTP_DUMP", path, MAX_PATH)) {
      rtp_dump_ = _wfsopen(path, L"wb", _SH_DENYWR);
      rtp_dump_t0_ = Clock::now();
      if (rtp_dump_) {
        log::info("ISS_RTP_DUMP: writing the video RTP and our RTCP");
      } else {
        log::warn("ISS_RTP_DUMP: cannot open the file");
      }
    }
    if (!opt_.media) {  // TCPのみ: 名前のどのアドレスを使ってもよい
      dest_.text = opt_.host;
      stop_ = false;
      connect_framebuffer();
      return;
    }
    // 2台目のディスプレイはカーテン（仮想ディスプレイ）のときにしか存在しない。
    if (opt_.display2 && !opt_.curtain && !opt_.alt_session) {
      log::warn("a second display needs the curtain (virtual displays); showing one");
      opt_.display2.reset();
    }
    dest_ = net::resolve_media_host(opt_.host, opt_.family);
    if (dest_.text != opt_.host) {
      log::info("resolved {} -> {} (IPv{} for the control connection and the media path)", opt_.host, dest_.text,
                dest_.v6 ? 6 : 4);
    }
    ctrl_port_ = opt_.port;
    sock_ctrl_ = net::UdpSocket::bind(ctrl_port_);
    for (int i = 0; i < (opt_.display2 ? 2 : 1); ++i) {
      auto s = std::make_unique<VideoStream>();
      s->index = i;
      s->port = static_cast<uint16_t>(opt_.port + 1 + i);
      s->sock = net::UdpSocket::bind(s->port);
      streams_.push_back(std::move(s));
    }
    log::info("UDP bound: ctrl :{} video :{}{} -> {}", sock_ctrl_.local_port(), streams_[0]->sock.local_port(),
              streams_.size() > 1 ? std::format(" second display :{}", streams_[1]->sock.local_port()) : "", dest_.text);
    stop_ = false;
    for (auto& s : streams_) threads_.emplace_back([this, st = s.get()] { video_rx_loop(*st); });
    threads_.emplace_back([this] { ctrl_rx_loop(); });
    negotiate_and_wait_for_burst();
  } catch (...) {
    stop();
    throw;
  }
}

proto::ConnectOptions Session::connect_options() const {
  proto::ConnectOptions c;
  c.host = dest_.text;
  c.port = opt_.port;
  c.username = opt_.username;
  c.password = opt_.password;
  c.auth_mode = opt_.auth_mode;
  c.display = opt_.display;
  c.display2 = opt_.display2;
  c.curtain = opt_.curtain;
  c.legacy_cursor = opt_.legacy_cursor;
  c.share_console = opt_.share_console;
  c.alt_session = opt_.alt_session;
  c.on_session_choice = opt_.on_session_choice;
  c.warmup = opt_.warmup;
  c.timing = opt_.timing;
  c.media = opt_.media;
  c.encodings = opt_.encodings;
  return c;
}

// 標準モード: メディアの提示なしでハンドシェイクする。画面は制御チャネル上の
// framebuffer updateとして届く（tcp-rxスレッド）。
void Session::connect_framebuffer() {
  proto::ConnectOptions c = connect_options();
  c.display2.reset();
  try {
    neg_ = proto::connect_and_negotiate(c);
  } catch (...) {
    secure_wipe(c.password);
    throw;
  }
  secure_wipe(c.password);
  canvas_w_ = neg_->server_width;
  canvas_h_ = neg_->server_height;
  const Bytes& pf = neg_->server_pixel_format;
  if (pf.size() >= 13 && !(pf[0] == 32 && pf[2] == 0 && pf[3] && pf[10] == 16 && pf[11] == 8 && pf[12] == 0)) {
    log::warn("standard mode: unexpected pixel format; Raw / zlib / ZRLE colours will be wrong");
  }
  {
    std::lock_guard lk(fb_mu_);
    fb_.resize(canvas_w_, canvas_h_);
  }
  waiting_key_ = true;
  alive_ = true;
  log::info("session up (standard mode): {}x{}{}", canvas_w_.load(), canvas_h_.load(),
            neg_->alt_session ? ", alt session" : "");
  threads_.emplace_back([this] { tcp_rx_loop(); });
  threads_.emplace_back([this] { fb_tx_loop(); });
}

// 標準モードで、更新ごとの要求とは別に送る要求。ホストは1回の要求に1回分の
// 変更で答えるので、その連鎖が止まったときに備えて、全画面のインクリメンタルな
// 要求もkFbPollMsごとに送る。実験用の設定: ISS_FB_POLL_MS（その周期）、
// ISS_FB_FULL_AFTER_MS（N ms後に非インクリメンタルな要求を1回）。
void Session::fb_tx_loop() {
  auto env_ms = [](const char* name) -> int64_t {
    char buf[32] = {};
    return GetEnvironmentVariableA(name, buf, sizeof(buf)) ? std::atoll(buf) : 0;
  };
  constexpr int64_t kFbPollMs = 500;
  const int64_t poll = env_ms("ISS_FB_POLL_MS") ? env_ms("ISS_FB_POLL_MS") : kFbPollMs;
  const int64_t full_after = env_ms("ISS_FB_FULL_AFTER_MS");
  // ISS_FB_SWITCH_AFTER_MS + ISS_FB_SWITCH_ENCODINGS: SetEncodingsを送り直して
  // 全画面を要求する（同じ画面を別のコーデックで受け取り、比べる基準にする）。
  const int64_t switch_after = env_ms("ISS_FB_SWITCH_AFTER_MS");
  std::vector<int32_t> switch_encodings;
  {
    char buf[256] = {};
    if (GetEnvironmentVariableA("ISS_FB_SWITCH_ENCODINGS", buf, sizeof(buf))) {
      for (const char* p = buf; *p;) {
        switch_encodings.push_back(std::atoi(p));
        while (*p && *p != ',') ++p;
        if (*p == ',') ++p;
      }
    }
  }
  // ISS_FB_POINTER_PATH "x,y;x,y;..." + ISS_FB_POINTER_STEP_MS: ポインタを
  // 決まった位置に順に動かす（画面に描き込まれたカーソルを既知の内容として、
  // コーデックの解析に使う）。
  std::vector<std::pair<int, int>> path;
  {
    char buf[4096] = {};
    if (GetEnvironmentVariableA("ISS_FB_POINTER_PATH", buf, sizeof(buf))) {
      for (const char* p = buf; *p;) {
        const int x = std::atoi(p);
        while (*p && *p != ',') ++p;
        if (*p) ++p;
        const int y = std::atoi(p);
        while (*p && *p != ';') ++p;
        if (*p) ++p;
        path.emplace_back(x, y);
      }
    }
  }
  const int64_t step_ms = env_ms("ISS_FB_POINTER_STEP_MS") ? env_ms("ISS_FB_POINTER_STEP_MS") : 500;
  size_t path_i = 0;
  const int64_t start = now_ms();
  int64_t next_poll = poll ? start + poll : 0, next_step = start + 2000;
  bool full_sent = full_after == 0, switched = switch_after == 0 || switch_encodings.empty();
  while (!stop_) {
    const int64_t t = now_ms();
    const auto w = static_cast<uint16_t>(canvas_w_.load()), h = static_cast<uint16_t>(canvas_h_.load());
    if (!full_sent && t - start >= full_after) {
      send_control(rfb::build_fbu_request(false, 0, 0, w, h));
      log::info("standard mode: full update requested");
      full_sent = true;
    }
    if (!switched && t - start >= switch_after) {
      set_encodings(switch_encodings);
      switched = true;
    }
    if (next_poll && t >= next_poll) {
      send_control(rfb::build_fbu_request(true, 0, 0, w, h));
      next_poll = t + poll;
    }
    if (path_i < path.size() && t >= next_step) {
      send_pointer(0, path[path_i].first, path[path_i].second);
      log::info("pointer test: {},{}", path[path_i].first, path[path_i].second);
      ++path_i;
      next_step = t + step_ms;
    }
    std::unique_lock lk(tx_mu_);
    tx_cv_.wait_for(lk, std::chrono::milliseconds(20), [this] { return stop_.load(); });
  }
}

void Session::negotiate_and_wait_for_burst() {
  proto::OfferOptions oo = proto::OfferOptions::from_env();
  if (env_set("ISS_VIDEO_CODEC") && oo.codec != proto::VideoCodec::Avc) {
    log::warn("ISS_VIDEO_CODEC ignored: iss-win decodes H.264 only for now");
  }
  const bool hevc = opt_.hevc || opt_.hevc_probe;
  oo.codec = hevc ? proto::VideoCodec::Hevc : proto::VideoCodec::Avc;
  // VideoSettingsのfield 8（Appleは63を送る）のbit 3が4:4:4を求める。このビットが
  // なければMacはHEVC 4:2:0で送る（2026-10-09に1ビットずつ落として確かめた）。
  if (opt_.hevc420) oo.video_f8 = oo.video_f8.value_or(63) & ~uint64_t{8};
  oo.video_streams = static_cast<int>(streams_.size());
  // 音声はPythonクライアントの既定の経路と同じく有効のままにする（どのみち0x1cには
  // 有効な音声セクションが要る）。プレーヤーができるまで、音声パケットは読んで捨てる。
  tiles_ = oo.tiles();
  VideoStream& main = *streams_[0];

  std::vector<proto::RtpPacket> burst;
  size_t last_count = 0;
  for (int attempt = 1;; ++attempt) {
    const proto::Offers offers = proto::create_offers(oo);
    main.our_ssrc = proto::extract_offer_ssrc(offers.video, true).value_or(0);
    our_audio_ssrc_ = proto::extract_offer_ssrc(offers.audio, false).value_or(0);
    if (streams_.size() > 1) streams_[1]->our_ssrc = proto::extract_offer_ssrc(offers.video2, true).value_or(0);
    for (const auto& s : streams_) {
      if (!s->our_ssrc) throw std::runtime_error("internal error: offer without an SSRC");
    }
    if (!our_audio_ssrc_) throw std::runtime_error("internal error: offer without an SSRC");
    log::info("our SSRCs: video=0x{:08x}{} audio=0x{:08x}; {}, {} tile(s)", main.our_ssrc,
              streams_.size() > 1 ? std::format(" video2=0x{:08x}", streams_[1]->our_ssrc) : "", our_audio_ssrc_,
              hevc ? "HEVC" : "H.264", tiles_);

    proto::ConnectOptions c = connect_options();
    c.offers = offers;

    for (const auto& s : streams_) {
      std::lock_guard lk(s->q_mu);
      s->q.clear();  // 前の試行の残りはどうせ復号できない
    }
    // ハンドシェイクの間ずっと穴あけを続ける。ホストは縮退したキャンバスの
    // 再問い合わせ中、こちらに制御が戻る前に送信を始めることがある。
    punching_ = true;
    punch_thread_ = std::thread([this] { firewall_punch_loop(); });
    auto stop_punching = [this] {
      punching_ = false;
      if (punch_thread_.joinable()) punch_thread_.join();
    };
    try {
      neg_ = proto::connect_and_negotiate(c);
    } catch (...) {
      secure_wipe(c.password);
      stop_punching();
      throw;
    }
    secure_wipe(c.password);

    const proto::NegotiationKeys& k = neg_->keys;
    main.dec = std::make_unique<proto::SrtpDecryptor>(k.video_key_s);
    main.srtcp = std::make_unique<proto::SrtcpEncryptor>(k.video_key_v);
    if (streams_.size() > 1) {
      streams_[1]->dec = std::make_unique<proto::SrtpDecryptor>(k.video2_key_s);
      streams_[1]->srtcp = std::make_unique<proto::SrtcpEncryptor>(k.video2_key_v);
    }
    audio_enc_ = std::make_unique<proto::SrtpEncryptor>(k.audio_key_v, our_audio_ssrc_);

    burst = collect_burst();
    stop_punching();
    if (opt_.hevc_probe) {
      const std::string report = hevc_probe_report(burst, neg_->canvas);
      neg_->sock.close();
      neg_.reset();
      throw std::runtime_error(report);
    }

    const auto map = complete_tiles(primary_ssrc_group(main.dec->counts(), tiles_), tiles_);
    std::optional<media::AvcConfig> cfg;
    if (opt_.hevc) {
      // パラメータセットはストリームの中で届く（キーフレームの前のaggregation
      // packet）。どのタイルも同じものを運ぶ。
      main.vps.clear();
      media::AvcConfig ps;
      for (const auto& [key, payloads] : burst_units(burst)) {
        if (!map.count(key.first)) continue;
        for (const Bytes& nal : media::hevc_reassemble_group(payloads)) {
          const int t = nal.size() >= 2 ? media::hevc_nal_type(nal[0]) : -1;
          if (t == media::HEVC_NAL_VPS && main.vps.empty()) main.vps = nal;
          if (t == media::HEVC_NAL_SPS && ps.sps.empty()) ps.sps = nal;
          if (t == media::HEVC_NAL_PPS && ps.pps.empty()) ps.pps = nal;
        }
      }
      if (!main.vps.empty() && !ps.sps.empty() && !ps.pps.empty()) cfg = std::move(ps);
    } else {
      for (const proto::RtpPacket& p : burst) {
        if (map.count(p.ssrc) && !p.payload.empty() && p.payload[0] == media::APPLE_AVC_CONFIG_MARKER) {
          if (auto c2 = media::parse_avc_config(p.payload)) cfg = std::move(c2);
        }
      }
    }
    last_count = burst.size();
    if (!map.empty() && cfg) {
      std::lock_guard lk(state_mu_);
      main.ssrc_to_tile = map;
      main.sps = cfg->sps;
      main.pps = cfg->pps;
      if (opt_.hevc) {
        const auto info = media::parse_hevc_sps(main.sps);
        log::info("video SSRC group: {}; HEVC tiles {}x{}, VPS {} B, SPS {} B, PPS {} B", ssrc_list(map),
                  info ? info->width : 0, info ? info->height : 0, main.vps.size(), main.sps.size(), main.pps.size());
      } else {
        log::info("video SSRC group: {}; SPS {} B, PPS {} B", ssrc_list(map), main.sps.size(), main.pps.size());
      }
      break;
    }
    const char* reason = burst.size() < 20 ? "no video RTP arrived"
                         : opt_.hevc      ? "no HEVC parameter sets (VPS/SPS/PPS) in the burst"
                                          : "no H.264 config (SPS/PPS) in the burst";
    // ホストはキャンバスを受け入れたのに送信を始めなかった。ScreensharingAgentが
    // 固まっている。TCPを切ると新しいものが起動する。
    log::warn("start burst starved: {} ({} packets); full reconnect {}/{}", reason, burst.size(), attempt,
              kBurstAttempts);
    neg_->sock.close();
    neg_.reset();
    if (attempt >= kBurstAttempts) {
      throw std::runtime_error(std::format(
          "the video stream never started ({} packets in the last of {} handshakes). If none arrived, Windows "
          "Firewall may be blocking UDP {}-{} for iss-win; otherwise toggle Screen Sharing off and on on the Mac "
          "and try again.",
          last_count, kBurstAttempts, ctrl_port_, streams_.back()->port));
    }
    std::this_thread::sleep_for(kBurstRetrySleep);
  }

  if (neg_->canvas.valid()) {
    canvas_w_ = neg_->canvas.width;
    canvas_h_ = neg_->canvas.height;
  }
  if (!opt_.hevc || !neg_->canvas.ltrp.value_or(0)) ltr_ack_ = LtrAck::Off;
  if (opt_.hevc) {
    log::info("LTR acks: {}", ltr_ack_ == LtrAck::Off ? "off" : ltr_ack_ == LtrAck::Tile0 ? "strip 0" : "every strip");
  }
  if (opt_.hevc) {
    open_hevc_decoder(main);
  } else {
    main.decoder.open({media::Codec::H264, opt_.prefer_hwaccel, opt_.adapter_index}, avc_extradata(main.sps, main.pps));
  }
  for (auto& s : streams_) make_grouper(*s);
  alive_ = true;
  log::info("session up: canvas {}x{}, server {}x{}{}{}", canvas_w_.load(), canvas_h_.load(), neg_->server_width,
            neg_->server_height, neg_->alt_session ? ", alt session" : "",
            streams_.size() > 1 ? ", two displays" : "");
  threads_.emplace_back([this, b = std::move(burst)]() mutable { video_loop(*streams_[0], std::move(b)); });
  // 2台目のディスプレイのストリームは専用のまとまりなしで始まる。最初のSSRC
  // グループには移ったストリームと同じように乗り換え、始まりの部分を流し直す。
  for (size_t i = 1; i < streams_.size(); ++i) {
    threads_.emplace_back([this, st = streams_[i].get()] { video_loop(*st, {}); });
  }
  threads_.emplace_back([this] { tcp_rx_loop(); });
  threads_.emplace_back([this] { tx_loop(); });
}

// そろわないピクチャはkQuickRepairWaitであきらめる。Macは再送をほぼしないうえ、
// 同じストリームの後続のピクチャがその後ろで待たされる（実験用にISS_REPAIR_MSで
// 上書きできる）。
RtpGrouper::Timing Session::repair_timing() const {
  RtpGrouper::Timing t;
  t.repair_wait = kQuickRepairWait;
  if (char ms[16] = {}; GetEnvironmentVariableA("ISS_REPAIR_MS", ms, sizeof(ms))) {
    t.repair_wait = std::chrono::milliseconds(std::clamp(std::atoi(ms), 0, 1000));
  }
  return t;
}

void Session::make_grouper(VideoStream& s) {
  s.grouper = std::make_unique<RtpGrouper>(RtpGrouper::Output{
      [this, &s](uint32_t ssrc, uint32_t ts, std::vector<Bytes>&& payloads) {
        on_access_unit(s, ssrc, ts, std::move(payloads));
      },
      [this, &s](uint32_t ssrc, uint32_t, const char* reason, Clock::time_point arrival) {
        int tile = 0;
        {
          std::lock_guard lk(state_mu_);
          if (auto it = s.ssrc_to_tile.find(ssrc); it != s.ssrc_to_tile.end()) tile = it->second;
        }
        if (opt_.hevc) {
          // 壊れたのはこの帯だけ。デコーダはそのまま続け、失ったピクチャを
          // 参照するピクチャは飛ばす。リフレッシュ要求はたいていDONLの抜けの
          // 時点で送ってあり、ここでは最近の要求がないとき（止まる直前の損失）
          // だけ要求する。最新のIDRより前に始まったユニットはそのIDRで
          // リフレッシュされている。
          if (n_dropped_++ < 20) log::info("stream {}: strip {} lost a picture ({})", s.index, tile, reason);
          if (arrival < s.last_idr_at) return;
          s.stale_since.try_emplace(tile, arrival);
          s.keyframe_wanted = true;
          wake_tx();
          return;
        }
        s.stale_since.try_emplace(tile, arrival);
        // H.264: ピクチャ全体がキーフレームを待つ。要求はたいていシーケンスの
        // 抜けの時点で送ってある。デコーダはキーフレームが届いてからではなく、
        // 届くまでの間の今作り直す（D3D11VAで40-60 ms）。
        if (n_dropped_++ < 20) log::info("stream {}: frame dropped ({}); waiting for a keyframe", s.index, reason);
        s.keyframe_wanted = true;
        wake_tx();
        if (!s.decoder.waiting_for_keyframe()) s.decoder.reset_now();
      },
      [this](uint32_t, uint16_t seq, std::chrono::milliseconds after_drop) {
        if (n_late_++ < 20) {
          log::info("late packet seq {} for a frame dropped {} ms earlier (a NACK retransmit?)", seq, after_drop.count());
        }
      }},
      repair_timing());
  // ISS_NO_PICTURE_SYNC: 9404bcbより前と同じく、各帯をデコードしたらすぐ画面に
  // 出す（そのコミットで直したテアリングを見るため）。
  static const bool no_sync = env_set("ISS_NO_PICTURE_SYNC");
  if (no_sync && tiles_ > 1 && s.index == 0) log::info("ISS_NO_PICTURE_SYNC: strips are shown as they are decoded");
  std::lock_guard lk(frame_mu_);
  s.assembler = std::make_unique<PictureAssembler>(no_sync ? 1 : tiles_, kTileGap);
}

// メインディスプレイのセッション開始時のまとまり。H.264の設定を受け取ったあと
// ストリームがkBurstQuietMs途切れるまでのすべてのパケットで、上限はkBurstMax。
std::vector<proto::RtpPacket> Session::collect_burst() {
  VideoStream& s = *streams_[0];
  std::vector<proto::RtpPacket> out;
  bool have_config = false;
  const auto deadline = Clock::now() + kBurstMax;
  while (Clock::now() < deadline && !stop_) {
    auto raw = pop_video(s, kBurstQuietMs);
    if (!raw) {
      if (have_config && !out.empty()) break;
      continue;
    }
    if (auto p = s.dec->decrypt(raw->data)) {
      if (rtp_dump_) dump_packet(DumpKind::Rx, raw->data.data(), p->header_len, p->payload, raw->at);
      have_config = have_config || (opt_.hevc ? hevc_payload_has_params(p->payload)
                                              : !p->payload.empty() && p->payload[0] == media::APPLE_AVC_CONFIG_MARKER);
      out.push_back(std::move(*p));
      if (have_config && out.size() >= kBurstEnoughPackets) break;
    }
  }
  log::info("start burst: {} packets{}", out.size(),
            have_config ? "" : opt_.hevc ? " (no HEVC parameter sets yet)" : " (no H.264 config yet)");
  return out;
}

void Session::stop() {
  stop_ = true;
  punching_ = false;
  wake_tx();
  for (auto& s : streams_) s->q_cv.notify_all();
  if (punch_thread_.joinable()) punch_thread_.join();
  for (std::thread& t : threads_) {
    if (t.joinable()) t.join();
  }
  threads_.clear();
  alive_ = false;
  {
    std::lock_guard lk(send_mu_);
    if (neg_) {
      neg_->sock.shutdown();
      neg_->sock.close();
      secure_wipe(neg_->ecb_key);
      neg_.reset();
    }
  }
  sock_ctrl_.close();
  for (auto& s : streams_) {
    s->sock.close();
    s->decoder.close();
  }
  if (dump_) {
    std::fclose(dump_);
    dump_ = nullptr;
  }
  std::lock_guard lk(rtp_dump_mu_);
  if (rtp_dump_) {
    std::fclose(rtp_dump_);
    rtp_dump_ = nullptr;
  }
}

// レコード: 種別（u8）、0を3バイト、長さ（u32 LE）、ダンプを開いてからの
// マイクロ秒（i64 LE）、続いてパケット（RTPヘッダ + 平文のペイロード、または
// 平文のRTCP）。
void Session::dump_packet(DumpKind kind, const uint8_t* head, size_t head_len, const Bytes& body, Clock::time_point at) {
  std::lock_guard lk(rtp_dump_mu_);
  if (!rtp_dump_) return;
  uint8_t rec[16] = {static_cast<uint8_t>(kind)};
  const auto len = static_cast<uint32_t>(head_len + body.size());
  const int64_t us = std::chrono::duration_cast<std::chrono::microseconds>(at - rtp_dump_t0_).count();
  std::memcpy(rec + 4, &len, 4);
  std::memcpy(rec + 8, &us, 8);
  std::fwrite(rec, 1, sizeof(rec), rtp_dump_);
  if (head_len) std::fwrite(head, 1, head_len, rtp_dump_);
  if (!body.empty()) std::fwrite(body.data(), 1, body.size(), rtp_dump_);
}

bool Session::test_loss() {
  if (!loss_permille_) return false;
  loss_rng_ ^= loss_rng_ << 13;  // xorshift64
  loss_rng_ ^= loss_rng_ >> 7;
  loss_rng_ ^= loss_rng_ << 17;
  return loss_rng_ % 1000 < loss_permille_;
}

void Session::wake_tx() {
  {
    std::lock_guard lk(tx_mu_);
    tx_wake_ = true;
  }
  tx_cv_.notify_one();
}

void Session::firewall_punch_loop() {
  // 各メディアソケットからホストの対応するポートへ1バイト送る。これでホストから
  // のメディアが戻りの通信として扱われ、受信側のファイアウォール規則が要らなくなる。
  // RTPとしては短すぎるので、ホストは捨てる。
  static const Bytes kPunch = {0x00};
  while (punching_ && !stop_) {
    sock_ctrl_.send_to(dest_, ctrl_port_, kPunch);
    for (const auto& s : streams_) s->sock.send_to(dest_, s->port, kPunch);
    std::this_thread::sleep_for(100ms);
  }
}

// ── ビデオ ───────────────────────────────────────────────────────────────

std::optional<Session::RxPacket> Session::pop_video(VideoStream& s, int timeout_ms) {
  std::unique_lock lk(s.q_mu);
  if (!s.q_cv.wait_for(lk, std::chrono::milliseconds(timeout_ms), [&] { return !s.q.empty() || stop_; })) {
    return std::nullopt;
  }
  if (s.q.empty()) return std::nullopt;
  RxPacket p = std::move(s.q.front());
  s.q.pop_front();
  return p;
}

void Session::video_rx_loop(VideoStream& s) {
  bool first = true;
  while (!stop_) {
    std::optional<Bytes> pkt;
    try {
      pkt = s.sock.recv(200);
    } catch (const net::NetError& e) {
      if (!stop_) fail(std::format("video socket {}: {}", s.port, e.what()));
      return;
    }
    const auto at = Clock::now();
    if (!pkt || pkt->size() < 12) continue;
    // ホストはビデオストリームのRTCPをこのポートに多重化する。パケットタイプは
    // 192..207（legacy FIR .. PSFB）。ビデオのRTPは動的ペイロードタイプ（96以上）
    // なので、2バイト目は128未満か、マーカー付きなら224以上になる。
    if ((*pkt)[1] >= 192 && (*pkt)[1] <= 207) {
      ++n_video_rtcp_;
      continue;
    }
    if (first) {
      log::info("video UDP {}: first packet ({} B)", s.port, pkt->size());
      first = false;
    }
    ++n_packets_;
    n_bytes_ += pkt->size();
    {
      std::lock_guard lk(s.q_mu);
      if (s.q.size() >= kVideoQueueMax) {
        ++n_queue_drops_;
        continue;
      }
      s.q.push_back({std::move(*pkt), at});
    }
    s.q_cv.notify_one();
  }
}

void Session::video_loop(VideoStream& s, std::vector<proto::RtpPacket> burst) {
  try {
    const auto start = Clock::now();
    s.last_mapped = start;
    s.fast_adopt_until_ms = now_ms() + kFastAdoptWindowMs;
    for (proto::RtpPacket& p : burst) handle_rtp(s, std::move(p), start);
    burst.clear();
    auto last_evict = start;
    Clock::time_point last_rx{};
    while (!stop_) {
      auto raw = pop_video(s, 20);
      const auto now = Clock::now();
      if (raw) {
        last_rx = raw->at;
        if (auto p = s.dec->decrypt(raw->data)) {
          const bool lose = s.index == 0 && test_loss();
          if (rtp_dump_ && s.index == 0) {
            dump_packet(lose ? DumpKind::Lost : DumpKind::Rx, raw->data.data(), p->header_len, p->payload, raw->at);
          }
          if (!lose) handle_rtp(s, std::move(*p), raw->at);
        }
      }
      if (now - last_evict >= 20ms) {
        // grouperの期限は到着時刻で進む。滞留があるとき（デコーダの作り直し、
        // 開始時のまとまり）は、ユニットをそろえるパケットがまだキューにある。
        // 期限切れにするのは取り出し済みの分までにとどめる。
        bool backlog = false;
        {
          std::lock_guard lk(s.q_mu);
          backlog = !s.q.empty();
        }
        s.grouper->evict(backlog && last_rx != Clock::time_point{} ? last_rx : now);
        maybe_adopt_ssrcs(s, now);
        s.repaired = s.grouper->repaired();
        last_evict = now;
      }
    }
  } catch (const std::exception& e) {
    fail(std::format("video {}: {}", s.index, e.what()));
  }
}

void Session::handle_rtp(VideoStream& s, proto::RtpPacket&& pkt, Clock::time_point rx) {
  int tile = 0;
  {
    std::lock_guard lk(state_mu_);
    if (auto it = s.ssrc_to_tile.find(pkt.ssrc); it != s.ssrc_to_tile.end()) tile = it->second;
    if (!s.ssrc_to_tile.count(pkt.ssrc)) {
      if (s.unknown_counts[pkt.ssrc]++ == 0) {
        log::info("video {}: packets from SSRC 0x{:08x}, outside our group ({})", s.index, pkt.ssrc,
                  ssrc_list(s.ssrc_to_tile));
      }
      ++n_unknown_;
      auto& q = s.unknown_packets[pkt.ssrc];
      if (q.size() >= kUnknownSsrcBuffer) q.pop_front();
      q.push_back(std::move(pkt));
      return;
    }
  }
  s.last_mapped = rx;
  s.last_packet_ms = now_ms();
  const bool gap = track_seq(s, pkt.ssrc, pkt.seq);
  const bool apple_ext = pkt.ext_profile == 0x9301 || pkt.ext_profile == 0x9311;
  // パケットのピクチャ番号。HEVCはDONL（帯のピクチャごとに1つ）、H.264は
  // ヘッダ拡張の下位16ビット。
  std::optional<uint16_t> pic;
  if (opt_.hevc) {
    pic = media::hevc_payload_donl(pkt.payload);
  } else if (apple_ext) {
    pic = static_cast<uint16_t>(pkt.ext_word);
  }
  if (gap) on_packet_gap(s, pkt.ssrc, pic);
  if (pic) s.last_pkt_pic[pkt.ssrc] = *pic;
  if (opt_.perf && s.index == 0) {
    auto [it, fresh] = au_rx_.try_emplace(pkt.ts, AuArrival{rx, rx});
    if (!fresh) it->second.last = std::max(it->second.last, rx);
    if (au_rx_.size() > 64) au_rx_.erase(au_rx_.begin());  // そろわなかったユニット
  }
  if (tiles_ > 1) {
    std::lock_guard lk(frame_mu_);
    // `rx`ではなく処理する時刻を使う。滞留があるとき（開始時のまとまり）は、次の帯は
    // とうに届いていて、今になってデコードしているだけだ。
    if (!s.assembler->empty()) {
      show_frames_locked(s, s.assembler->packet(pkt.ts, Clock::now(), s.grouper->pending_ts(s.assembler->ts())));
    }
  }
  const uint16_t packets = apple_ext ? static_cast<uint16_t>(pkt.ext_word >> 16) : 0;
  // IDR（リフレッシュ要求への応答か、Macが自分から送ったもの）。HEVCのIDRは
  // パラメータセットで始まり、続くDONLで帯1-3のIピクチャが同じくパラメータ
  // セット付きで来る。そのため、IDRの先頭を失ってもどれか1つで時期がわかる。
  // H.264のIDRはキーフレーム。
  if (pic && (opt_.hevc ? hevc_payload_has_params(pkt.payload) : media::avc_payload_starts_keyframe(pkt.payload))) {
    // 新しいIDRだけを数える。要求を送った時点で届いていたIDRの帯を、その要求への
    // 応答と取り違えないため。
    const uint16_t idr = opt_.hevc ? static_cast<uint16_t>(*pic - tile) : *pic;
    if (s.last_idr_pic != idr) {
      s.last_idr_pic = idr;
      s.last_idr_at = rx;
      s.answer_seen = true;
    }
  }
  s.grouper->add(pkt.ssrc, pkt.ts, pkt.seq, pkt.marker, std::move(pkt.payload), rx, packets);
}

bool Session::track_seq(VideoStream& s, uint32_t ssrc, uint16_t seq) {
  bool loss = false;
  {
    std::lock_guard lk(state_mu_);
    auto [it, inserted] = s.seq.try_emplace(ssrc);
    SeqState& st = it->second;
    if (inserted) {
      st.max_seq = seq;
      return false;
    }
    const auto diff = static_cast<uint16_t>(seq - st.max_seq);
    if (diff == 0) return false;  // 重複
    if (diff > 0x8000) {          // 遅れて届いたか再送されたもの。もうNACKする意味はない
      s.nack_pending[ssrc].erase(seq);
      return false;
    }
    for (uint16_t m = 1; m < std::min<uint16_t>(diff, 32); ++m) {
      s.nack_pending[ssrc].insert(static_cast<uint16_t>(st.max_seq + m));
      ++n_lost_;
      loss = true;
    }
    if (seq < st.max_seq) ++st.roc;
    st.max_seq = seq;
  }
  if (loss) wake_tx();
  return loss;
}

// シーケンスの抜けの後に来たパケット。抜けの直前のパケットが同じピクチャ番号なら、
// 失ったパケットはこのパケットのピクチャに属する（ピクチャ内の抜け、特にIDRの抜けに、
// 次のピクチャがそろうのを待たずにすぐ気づける）。そうでなければ、そのSSRCの前の
// ピクチャの末尾とみなす。ピクチャの先頭やピクチャ全体を失った場合は、次の
// ピクチャがそろった時点でDONLの抜けとして見える。
void Session::on_packet_gap(VideoStream& s, uint32_t ssrc, std::optional<uint16_t> pic) {
  const auto prev = s.last_pkt_pic.find(ssrc);
  on_pictures_lost(s, pic && prev != s.last_pkt_pic.end() ? std::optional(prev->second) : std::nullopt);
  if (!opt_.hevc) {
    // H.264では、失ったのが独立した1枚のピクチャで、次のピクチャは欠けていない
    // （パケット数でわかる）こともある。どちらにせよ参照の連鎖は切れている。
    // 要求は送ってあるので、デコーダは最初からやり直してキーフレームを待つ。
    s.stale_since.try_emplace(0, Clock::now());
    if (!s.decoder.waiting_for_keyframe()) s.decoder.reset_now();
  }
}

// MacはNACKにほぼ応えないので、ピクチャの損失に気づいたらすぐリフレッシュを要求する。
// ただし、ほかで間に合う場合は除く。損失の後に来たIDRがある場合（最新のIDRが全部の帯を
// リフレッシュした）と、応答がまだ届き始めていない要求がある場合だ。応答そのものや、
// それより後のものを失ったら再度要求する。H.264では、キーフレームの先頭パケットを
// 失うと損失の時期がわからない。要求からkAvcAnswerMs経っても応答がなければ、
// 失ったとみなす。
void Session::on_pictures_lost(VideoStream& s, std::optional<uint16_t> last) {
  const int idr = s.last_idr_pic;
  if (last && idr >= 0 && static_cast<uint16_t>(*last - static_cast<uint16_t>(idr)) >= 0x8000) {
    log::debug("video {}: picture {} lost before IDR {}, which refreshed it", s.index, *last, idr);
    return;
  }
  s.last_loss_seen = Clock::now();
  const int64_t since = now_ms() - s.last_refresh_ms;
  const bool awaiting = since < retry_interval().count() && !s.answer_seen && (opt_.hevc || since < kAvcAnswerMs);
  log::debug("video {}: picture {} lost, {} ms after the request{}", s.index, last ? std::to_string(*last) : "?",
             since, awaiting ? "; its answer will refresh it" : "");
  if (awaiting) return;
  s.refresh_not_before_ms =
      std::chrono::duration_cast<std::chrono::milliseconds>(s.last_idr_at.time_since_epoch()).count() + kAfterIdrMs;
  s.keyframe_wanted = true;
  s.keyframe_now = true;
  wake_tx();
}

void Session::on_access_unit(VideoStream& s, uint32_t ssrc, uint32_t ts, std::vector<Bytes>&& payloads) {
  int tile = 0;
  {
    std::lock_guard lk(state_mu_);
    auto it = s.ssrc_to_tile.find(ssrc);
    if (it == s.ssrc_to_tile.end()) return;
    tile = it->second;
  }
  const bool perf = opt_.perf && s.index == 0;
  const auto taken = Clock::now();
  Clock::time_point received = taken;
  if (perf) {
    if (auto it = au_rx_.find(ts); it != au_rx_.end()) {
      received = it->second.last;
      perf_spread_.add(std::chrono::duration<double, std::milli>(it->second.last - it->second.first).count());
      au_rx_.erase(it);
    }
    perf_wait_.add(std::chrono::duration<double, std::milli>(taken - received).count());
    // Macのビデオ用RTPクロックは一般的な90 kHzではなく24 kHz（計測値: 60 Hzの
    // 1フレームあたり約400ティック）。
    if (perf_last_ts_) perf_rtp_step_.add(static_cast<int32_t>(ts - *perf_last_ts_) / 24.0);
    if (perf_last_complete_ != Clock::time_point{}) {
      perf_arrival_step_.add(std::chrono::duration<double, std::milli>(received - perf_last_complete_).count());
    }
    perf_last_ts_ = ts;
    perf_last_complete_ = received;
    size_t bytes = 0;
    for (const Bytes& p : payloads) bytes += p.size();
    perf_kb_.add(bytes / 1024.0);
  }
  std::vector<media::VideoFrame> frames;
  bool key = false;
  const auto decode_start = Clock::now();
  const bool decoded = opt_.hevc ? decode_hevc_unit(s, tile, ts, payloads, frames, key)
                                 : decode_avc_unit(s, tile, ts, payloads, frames, key);
  if (!decoded) return;
  s.waiting_key = s.decoder.waiting_for_keyframe();
  if (frames.empty()) return;
  if (perf) perf_decode_.add(std::chrono::duration<double, std::milli>(Clock::now() - decode_start).count());
  n_frames_ += frames.size();
  s.last_frame_ms = now_ms();
  if (key) {
    s.frames_since_key = 0;
    if (s.keyframe_wanted.exchange(false)) log::debug("video {}: keyframe decoded", s.index);
  } else {
    s.frames_since_key += frames.size();
  }
  {
    std::lock_guard lk(info_mu_);
    s.decoder_name = s.decoder.backend();
  }
  for (const media::VideoFrame& f : frames) note_strip_shown(s, f.tile);
  std::lock_guard lk(frame_mu_);
  for (media::VideoFrame& f : frames) {
    f.received = received;
    show_frames_locked(s, s.assembler->add(std::move(f), taken));
  }
}

void Session::note_strip_shown(VideoStream& s, int tile) {
  auto it = s.stale_since.find(tile);
  if (it == s.stale_since.end()) return;
  if (opt_.perf && s.index == 0) {
    const double ms = std::chrono::duration<double, std::milli>(Clock::now() - it->second).count();
    perf_stale_.add(ms);
    if (ms > 150) log::info("video {}: strip {} back {:.0f} ms after a loss", s.index, tile, ms);
  }
  s.stale_since.erase(it);
  // 壊れた帯がすべて戻った。リフレッシュ要求はもう送らない。
  if (opt_.hevc && s.stale_since.empty()) s.keyframe_wanted = false;
}

void Session::show_frames_locked(VideoStream& s, std::vector<media::VideoFrame>&& frames) {
  for (media::VideoFrame& f : frames) {
    if (s.index == 0 && canvas_w_ == 0) {  // 応答にキャンバスがなければピクチャの大きさに合わせる
      canvas_w_ = f.width;
      canvas_h_ = f.height;
    }
    auto [it, fresh] = s.latest.try_emplace(f.tile);
    if (!fresh && s.index == 0) ++n_replaced_;  // 前のフレームはUIに渡らなかった
    it->second = std::move(f);
  }
}

bool Session::decode_avc_unit(VideoStream& s, int tile, uint32_t ts, const std::vector<Bytes>& payloads,
                              std::vector<media::VideoFrame>& frames, bool& key) {
  // H.264のパラメータセットは、Apple独自の0x92の設定として単独のパケットで来るか
  // （メインディスプレイのストリーム。ジオメトリが変わった後にも来る）、キーフレームの
  // スライスと一緒にSTAP-Aに入って来る（2台目のディスプレイのストリーム）。または
  // 素のSPS / PPSのNALで来る。新しい組が来たら、このユニットのスライスをデコード
  // する前にデコーダを作る（作り直す）。
  std::optional<media::AvcConfig> cfg;
  auto take_config = [&](const Bytes& b) {
    if (auto c = media::parse_avc_config(b); c && !c->sps.empty()) cfg = std::move(c);
  };
  for (const Bytes& p : payloads) {
    if (!p.empty() && p[0] == media::APPLE_AVC_CONFIG_MARKER) take_config(p);
  }
  std::vector<Bytes> nals = media::avc_reassemble(payloads);
  {
    media::AvcConfig in_band;
    for (const Bytes& nal : nals) {
      if (nal[0] == media::APPLE_AVC_CONFIG_MARKER) take_config(nal);
      const int t = media::avc_nal_type(nal[0]);
      if (t == media::AVC_NAL_SPS) in_band.sps = nal;
      if (t == media::AVC_NAL_PPS) in_band.pps = nal;
    }
    if (!in_band.sps.empty() && !in_band.pps.empty()) cfg = std::move(in_band);
    std::erase_if(nals, [](const Bytes& nal) { return nal[0] == media::APPLE_AVC_CONFIG_MARKER; });
  }
  if (cfg && (cfg->sps != s.sps || cfg->pps != s.pps)) {
    log::info("video {}: {} H.264 config (SPS {} B, PPS {} B): {} the decoder", s.index, s.sps.empty() ? "first" : "new",
              cfg->sps.size(), cfg->pps.size(), s.sps.empty() ? "opening" : "rebuilding");
    s.sps = cfg->sps;
    s.pps = cfg->pps;
    s.decoder.open({media::Codec::H264, opt_.prefer_hwaccel, opt_.adapter_index}, avc_extradata(s.sps, s.pps));
    s.keyframe_wanted = true;
    wake_tx();
  }
  if (s.sps.empty()) return false;  // ストリームの設定が来るまでデコーダはない

  for (const Bytes& nal : nals) {
    key = key || media::avc_nal_is_keyframe(nal);
    s.decoder.decode(nal, tile, frames, ts);
  }
  return true;
}

void Session::open_hevc_decoder(VideoStream& s) {
  const auto info = media::parse_hevc_sps(s.sps);
  log::info("video {}: HEVC tiles {}x{} ({}): {} the decoder", s.index, info ? info->width : 0,
            info ? info->height : 0, info && info->chroma_format_idc == 3 ? "4:4:4" : "4:2:0",
            s.hevc_opened ? "rebuilding" : "opening");
  s.hevc_opened = true;
  s.hevc_reopen = false;
  s.refs.reset();
  if (!s.refs.set_sps(s.sps) || !s.refs.set_pps(s.pps)) {
    log::warn("video {}: HEVC parameter sets not understood; every picture is decoded as it comes", s.index);
  }
  if (!opt_.hevc420) {
    s.decoder.open({.codec = media::Codec::Hevc, .qsv = true}, {});
    return;
  }
  Bytes extradata;
  for (const Bytes* ps : {&s.vps, &s.sps, &s.pps}) {
    extradata.insert(extradata.end(), kStartCode.begin(), kStartCode.end());
    extradata.insert(extradata.end(), ps->begin(), ps->end());
  }
  s.decoder.open({media::Codec::Hevc, opt_.prefer_hwaccel, opt_.adapter_index}, extradata);
}

// パラメータセットはストリームの中で届き、どのタイルも同じものを持つ。新しいものが
// 来たら、このユニットのスライスより先にデコーダを開き直す。hevc_qsvは1パケットに
// ピクチャ1枚分を求める（qsvhevc.py）。このタイルのNALを1つのAnnex-Bユニットに
// まとめ、パラメータセットなしで来たキーフレームにはその前にパラメータセットを付ける。
// libavcodecにはスライスをNAL1つずつ渡す。パラメータセットはextradataに入れてある。
bool Session::decode_hevc_unit(VideoStream& s, int tile, uint32_t ts, const std::vector<Bytes>& payloads,
                               std::vector<media::VideoFrame>& frames, bool& key) {
  const std::vector<Bytes> nals = media::hevc_reassemble_group(payloads);
  bool params = false, slice = false;
  for (const Bytes& nal : nals) {
    if (nal.size() < 2) continue;
    const int t = media::hevc_nal_type(nal[0]);
    Bytes* ps = t == media::HEVC_NAL_VPS ? &s.vps : t == media::HEVC_NAL_SPS ? &s.sps : t == media::HEVC_NAL_PPS ? &s.pps : nullptr;
    if (ps) {
      params = true;
      if (*ps != nal) {
        *ps = nal;
        s.hevc_reopen = true;
      }
    } else if (t <= 31) {
      slice = true;
      key = key || media::hevc_is_irap(t);
    }
  }
  if (s.hevc_reopen && !s.vps.empty() && !s.sps.empty() && !s.pps.empty()) {
    open_hevc_decoder(s);
    s.keyframe_wanted = true;
    wake_tx();
  }
  if (!slice || !s.hevc_opened) return false;
  // DONLは帯をまたいでデコード順に続く。抜けはピクチャの損失で、その帯の次の
  // パケットを待たず、帯1つ分（約5 ms）後に気づける。同じ帯のそろわないピクチャの
  // 後ろで止められていたピクチャは、遅れて古い番号で来る。印を進めるのはより新しい
  // DONLだけ。
  const auto donl = media::hevc_first_donl(payloads);
  const auto step = donl && s.last_donl ? static_cast<uint16_t>(*donl - *s.last_donl) : uint16_t{1};
  if (donl && step < 0x8000) {
    if (step > 1) on_pictures_lost(s, static_cast<uint16_t>(*donl - 1));
    s.last_donl = donl;
  }
  // 失ったピクチャを（直接または間接に）参照するピクチャは外す。デコードしても
  // エラー隠蔽の画にしかならない。
  std::optional<media::HevcRefTracker::Picture> pic;
  for (const Bytes& nal : nals) {
    if (nal.size() >= 3 && media::hevc_nal_type(nal[0]) <= 31 && (nal[2] & 0x80)) {  // 最初のスライス
      pic = s.refs.ready() ? s.refs.add(nal) : std::nullopt;
      break;
    }
  }
  if (pic && !pic->clean) {
    log::debug("video {}: strip {} POC {} skipped (refers to a lost picture)", s.index, tile, pic->poc);
    ++n_skipped_;
    s.stale_since.try_emplace(tile, s.last_loss_seen != Clock::time_point{} ? s.last_loss_seen : Clock::now());
    return true;
  }
  if (opt_.hevc420) {
    for (const Bytes& nal : nals) {
      if (nal.size() >= 2) s.decoder.decode(nal, tile, frames, ts);
    }
  } else {
    Bytes au;
    auto put = [&](const Bytes& nal) {
      au.insert(au.end(), kStartCode.begin(), kStartCode.end());
      au.insert(au.end(), nal.begin(), nal.end());
    };
    if (key && !params) {
      for (const Bytes* ps : {&s.vps, &s.sps, &s.pps}) put(*ps);
    }
    for (const Bytes& nal : nals) {
      if (nal.size() >= 2) put(nal);
    }
    s.decoder.decode_au(au, tile, key, frames, ts);
  }
  std::erase_if(frames, [&](const media::VideoFrame& f) {
    if (!f.had_error) return false;
    // libavcodecはすぐ結果を返す。QSVのフレームはもっと前のピクチャのもの。
    if (opt_.hevc420 && pic && f.tile == tile) s.refs.mark_broken(pic->poc);
    s.stale_since.try_emplace(f.tile, Clock::now());
    ++n_skipped_;
    return true;
  });
  // QSVは非同期にデコードするので、ackは問題のないピクチャを渡した時点で送る。
  const bool decoded =
      !opt_.hevc420 || std::any_of(frames.begin(), frames.end(), [&](const media::VideoFrame& f) { return f.tile == tile; });
  if (donl && pic && decoded && (ltr_ack_ == LtrAck::All || (ltr_ack_ == LtrAck::Tile0 && tile == 0))) {
    send_ltr_ack(s, *donl);
  }
  return true;
}

std::string Session::stale_summary() {
  const std::vector<double> v = perf_stale_.take();
  return std::format("{} loss(es): {}", v.size(), PerfStat::summary("loss->strip back ms", v));
}

std::string Session::perf_line() {
  const std::vector<double> rtp = perf_rtp_step_.take();
  return std::format("perf: pictures {} | Mac step (60 Hz periods) {} | {} | {} | {} | {} | {} | {} | replaced before shown {} | {}",
                     rtp.size(), PerfStat::periods(rtp, 1000.0 / 60), PerfStat::summary("Mac step ms", rtp),
                     PerfStat::summary("arrival step ms", perf_arrival_step_.take()),
                     PerfStat::summary("first->last pkt ms", perf_spread_.take()),
                     PerfStat::summary("queue wait ms", perf_wait_.take()),
                     PerfStat::summary("decode ms", perf_decode_.take()), PerfStat::summary("size KB", perf_kb_.take()),
                     n_replaced_.exchange(0), stale_summary());
}

// Appleはセッションの途中でストリームを新しいSSRCグループに移すことがある
// （ディスプレイやセッションの切り替え）。自分のグループがkAdoptStallの間途切れたら、
// 最もパケットの多い未知のグループに乗り換える。2台目のディスプレイのストリームも
// こうして始まる。
void Session::maybe_adopt_ssrcs(VideoStream& s, Clock::time_point now) {
  const auto stall = now_ms() < s.fast_adopt_until_ms ? kAdoptStallEarly : kAdoptStall;
  if (s.unknown_counts.empty() || now - s.last_mapped < stall || now - s.last_adoption < kAdoptCooldown) {
    return;
  }
  // タイルがあるときは、送ってこない帯のSSRCも数に入れる。kAdoptMinPacketsは
  // グループ全体で満たせばよい。
  std::map<uint32_t, uint64_t> candidates;
  for (const auto& [ssrc, n] : s.unknown_counts) {
    if (n >= (tiles_ > 1 ? 1 : kAdoptMinPackets)) candidates[ssrc] = n;
  }
  auto map = primary_ssrc_group(candidates, tiles_);
  uint64_t group_packets = 0;
  for (const auto& [ssrc, tile] : map) group_packets += candidates[ssrc];
  if (map.empty() || group_packets < kAdoptMinPackets) return;
  map = complete_tiles(std::move(map), tiles_);
  log::warn("video {} moved to a new SSRC group: {}", s.index, ssrc_list(map));
  {
    std::lock_guard lk(state_mu_);
    s.ssrc_to_tile = map;
    s.seq.clear();
    s.nack_pending.clear();
  }
  s.grouper->reset();
  if (s.index == 0) {
    au_rx_.clear();
    perf_last_ts_.reset();
    perf_last_complete_ = {};
  }
  s.decoder.reset_on_next_keyframe();
  s.refs.reset();
  s.last_donl.reset();
  s.last_pkt_pic.clear();
  s.last_idr_pic = -1;
  s.last_idr_at = {};
  // 新しいストリームにすぐキーフレームを要求する（要求には宛先のSSRCが入るので、
  // これまでに送った要求は古いストリーム宛てだった）。
  s.keyframe_wanted = true;
  s.keyframe_now = true;
  wake_tx();
  // 新しいストリームがすでに送ったものを流し直す。その始まりにH.264の設定と
  // キーフレームが入っている。
  std::map<uint32_t, std::deque<proto::RtpPacket>> buffered;
  buffered.swap(s.unknown_packets);
  s.unknown_counts.clear();
  s.last_adoption = now;
  s.last_mapped = now;
  size_t replayed = 0;
  for (auto& [ssrc, packets] : buffered) {
    if (!map.count(ssrc)) continue;
    for (proto::RtpPacket& p : packets) {
      handle_rtp(s, std::move(p), now);
      ++replayed;
    }
  }
  log::info("video {}: replayed {} buffered packet(s) of the new stream", s.index, replayed);
}

std::optional<CursorRef> Session::take_cursor() {
  std::lock_guard lk(cursor_mu_);
  std::optional<CursorRef> out;
  out.swap(pending_cursor_);
  return out;
}

float Session::pixels_per_point() const {
  const float s = layout_scale_;
  return s > 0 ? s : static_cast<float>(std::max(1.0, opt_.display.hidpi_scale));
}

std::vector<media::VideoFrame> Session::take_frames(int stream) {
  std::vector<media::VideoFrame> out;
  if (stream < 0 || stream >= static_cast<int>(streams_.size())) return out;
  std::lock_guard lk(frame_mu_);
  VideoStream& s = *streams_[stream];
  if (s.assembler) show_frames_locked(s, s.assembler->poll(Clock::now()));
  auto& latest = s.latest;
  out.reserve(latest.size());
  for (auto& [tile, f] : latest) out.push_back(std::move(f));
  latest.clear();
  return out;
}

std::vector<rfb::DisplayRect> Session::display_rects() const {
  std::lock_guard lk(layout_mu_);
  return layout_ ? layout_->rects : std::vector<rfb::DisplayRect>{};
}

// ── 制御UDP、制御TCP ─────────────────────────────────────────────────────

// UDP 5900にはホストのRTCPと音声（プレーヤーができるまでは捨てる）が来る。
// ソケットのバッファが埋まらないよう読み出し、数だけ数える。Pythonクライアントは
// 実際にはホストのsender reportを解析していない（RTP/RTCPの判定で先にPTを0x7Fで
// マスクしている）ので、そのRRはLSR = DLSR = 0になる。こちらも同じにする。
void Session::ctrl_rx_loop() {
  while (!stop_) {
    std::optional<Bytes> p;
    try {
      p = sock_ctrl_.recv(200);
    } catch (const net::NetError&) {
      return;
    }
    if (!p || p->size() < 2) continue;  // タイムアウトか、自分が送った1バイトの穴あけパケット
    const bool rtcp = ((*p)[0] & 0xC0) == 0x80 && ((*p)[1] & 0x7F) >= 64 && ((*p)[1] & 0x7F) <= 95;  // RFC 5761
    ++(rtcp ? n_ctrl_rtcp_ : n_ctrl_other_);
    last_ctrl_rx_ms_ = now_ms();
  }
}

void Session::tcp_rx_loop() {
  net::TcpSocket& sock = neg_->sock;
  proto::StreamCipher& cipher = *neg_->cipher;
  Bytes buf = std::move(neg_->rx_pending);
  std::map<uint8_t, uint64_t> seen;
  auto handle = [&](const Bytes& msg) {
    if (msg.empty()) return;
    ++n_tcp_msgs_;
    if (seen[msg[0]]++ == 0) log::info("control channel: first message type 0x{:02x} ({} B)", msg[0], msg.size());
    if (msg[0] == rfb::SRV_FRAMEBUFFER_UPDATE) handle_fbu(msg);
    // MiscStatus: u8 type、pad、u16 length、u16 flags、u16 cmd。ハートビート以外の
    // コマンドは変化を知らせる（11 = ユーザーセッション）。
    if (msg[0] == kMsgMiscStatus && msg.size() >= 8) {
      const uint16_t cmd = rd_be16(&msg[6]);
      if (cmd != kMiscHeartbeat && cmd != kMiscHeartbeatAlt) log::info("control: MiscStatus cmd {} ({} B)", cmd, msg.size());
    }
  };
  // 1レコードが1メッセージ。ただし標準モードでは大きな更新が連続するレコードに
  // またがる（RFC §6.4.6）ので、更新がそろうまでつなげる。
  Bytes pending;
  auto on_record = [&](const Bytes& rec) {
    if (rec.empty()) return;
    if (dump_) {
      const uint32_t n = static_cast<uint32_t>(rec.size());
      std::fwrite(&n, 4, 1, dump_);
      std::fwrite(rec.data(), 1, rec.size(), dump_);
      std::fflush(dump_);
    }
    if (opt_.media) {
      handle(rec);
      return;
    }
    ++n_packets_;
    n_bytes_ += rec.size();
    if (pending.empty() && rec[0] != rfb::SRV_FRAMEBUFFER_UPDATE) {
      handle(rec);
      return;
    }
    pending.insert(pending.end(), rec.begin(), rec.end());
    while (!pending.empty()) {
      const size_t len = fbu_length(pending.data(), pending.size());
      if (len == 0) return;  // 残りは後のレコードで来る
      if (len == kUnknownLength) {  // 区切れないので、解析できる分だけ使う
        handle(pending);
        pending.clear();
        return;
      }
      Bytes msg(pending.begin(), pending.begin() + static_cast<std::ptrdiff_t>(len));
      pending.erase(pending.begin(), pending.begin() + static_cast<std::ptrdiff_t>(len));
      handle(msg);
      if (!pending.empty() && pending[0] != rfb::SRV_FRAMEBUFFER_UPDATE) {
        handle(pending);
        pending.clear();
      }
    }
  };
  for (const Bytes& m : neg_->leftover_msgs) on_record(m);
  while (!stop_) {
    std::optional<Bytes> chunk;
    try {
      chunk = sock.recv_some(65536, 500);
    } catch (const net::NetError& e) {
      if (!stop_) fail(std::string("control channel: ") + e.what());
      return;
    }
    if (!chunk) continue;
    if (chunk->empty()) {
      if (!stop_) fail("the Mac closed the control connection");
      return;
    }
    buf.insert(buf.end(), chunk->begin(), chunk->end());
    size_t used = 0;
    for (const Bytes& m : cipher.decrypt_stream(buf, &used)) on_record(m);
    buf.erase(buf.begin(), buf.begin() + static_cast<std::ptrdiff_t>(used));
  }
}

void Session::handle_fbu(const Bytes& msg) {
  const bool fb = !opt_.media;
  const FbuEvents ev = parse_fbu(msg, cursor_cache_, fb);
  // カーソルの形とピクセル以外は、ディスプレイやセッションの切り替え（リサイズ、
  // ロック画面、ログイン）の印。その後でストリームがおかしくなったときのために
  // ログに1行残す。
  const size_t pixel_rects = ev.pixels.size();
  if (ev.truncated || ev.encodings.size() > pixel_rects + std::count(ev.encodings.begin(), ev.encodings.end(),
                                                                     kEncCursorRect)) {
    std::string encs;
    for (int32_t e : ev.encodings) encs += std::format("{}{}", encs.empty() ? "" : " ", e);
    log::info("control: update with encodings [{}]{}", encs, ev.truncated ? " (walk stopped)" : "");
  }
  if (fb) apply_pixels(ev);
  if (!ev.cursors.empty()) {
    if (n_cursor_ < 3 && ev.cursors.back()) {
      log::info("cursor shape {}x{}, hotspot {},{}; {} canvas pixels per point", ev.cursors.back()->width,
                ev.cursors.back()->height, ev.cursors.back()->hot_x, ev.cursors.back()->hot_y, pixels_per_point());
    }
    n_cursor_ += ev.cursors.size();
    {
      std::lock_guard lk(cursor_mu_);
      pending_cursor_ = ev.cursors.back();
    }
    // デーモンはカーソルの送信を要求ごとに再開するので、もう一度要求する。RFB経由で
    // ビデオを返されないよう1x1にする（session.py、_handle_fbu）。標準モードでは
    // 1x1の要求を送ると次の更新がその範囲に絞られてしまう。
    if (!fb) send_control(rfb::build_fbu_request(true, 0, 0, 1, 1));
  }
  if (ev.layout) {
    const DisplayLayoutInfo& l = *ev.layout;
    std::optional<DisplayLayoutInfo> prev;
    {
      std::lock_guard lk(layout_mu_);
      prev = layout_;
      layout_ = l;
    }
    ++n_layouts_;
    const bool changed = !prev || l.backing_w != prev->backing_w || l.backing_h != prev->backing_h ||
                         l.scaled_w != prev->scaled_w || l.scaled_h != prev->scaled_h;
    // 最初のレイアウトは初期のジオメトリを確かめるだけ（session.py）。
    const bool resized = prev && (l.backing_w != prev->backing_w || l.backing_h != prev->backing_h);
    if (changed || (prev && l.rects.size() != prev->rects.size())) {
      log::info("display layout: {} display(s), {}x{} points, {}x{} pixels", l.displays, l.scaled_w, l.scaled_h,
                l.backing_w, l.backing_h);
      for (const rfb::DisplayRect& r : l.rects) {
        log::info("  display 0x{:x}: pixels {}x{} at {},{}; points {}x{} at {},{}", r.display_id, r.w, r.h, r.x, r.y,
                  r.pw, r.ph, r.px, r.py);
      }
    }
    if (l.scaled_w > 0 && l.backing_w > 0) layout_scale_ = static_cast<float>(l.backing_w) / l.scaled_w;
    if (l.backing_w > 0 && l.backing_h > 0) {
      canvas_w_ = l.backing_w;  // ポインタの座標は新しいキャンバスに合わせる
      canvas_h_ = l.backing_h;
    }
    if (fb) {
      // 画面のサイズを合わせ、RFCがレイアウトのたびに求める再開の手順を踏む。
      // AutoFrameBufferUpdateと全画面の要求。
      const auto w = static_cast<uint16_t>(canvas_w_.load()), h = static_cast<uint16_t>(canvas_h_.load());
      {
        std::lock_guard lk(fb_mu_);
        if (fb_.width() != w || fb_.height() != h) fb_.resize(w, h);
      }
      send_control(rfb::build_auto_fbu(0, 0, w, h));
      send_control(rfb::build_fbu_request(false, 0, 0, w, h));
      return;
    }
    // レイアウトはディスプレイやセッションの切り替えの印で、その後カーソルの送信が
    // 止まる。非インクリメンタルな要求を1回送って再開させる。
    send_control(rfb::build_fbu_request(false));
    // ジオメトリが変わるとエンコーダは止まり、メディアストリームを提示し直すまで
    // 再開しない（_schedule_post_layout_arm）。
    if (resized) reoffer_media(std::format("display resized to {}x{}", l.backing_w, l.backing_h));
  }
}

namespace {
const char* fb_encoding_name(int32_t e) {
  switch (e) {
    case 6: return "zlib (6)";
    case 16: return "ZRLE (16)";
    case 1000: return "black & white (1000)";
    case 1001: return "grays (1001)";
    case 1002: return "thousands of colours (1002)";
    case 1011: return "Apple DCT (1011)";
    default: return nullptr;  // Raw / CopyRect: 使用中のコーデック名をそのまま残す
  }
}
}  // namespace

void Session::apply_pixels(const FbuEvents& ev) {
  if (ev.desktop_size) {
    std::lock_guard lk(fb_mu_);
    fb_.resize(ev.desktop_size->first, ev.desktop_size->second);
    canvas_w_ = ev.desktop_size->first;
    canvas_h_ = ev.desktop_size->second;
    log::info("standard mode: desktop size {}x{}", canvas_w_.load(), canvas_h_.load());
  }
  if (ev.pixels.empty()) return;
  const char* name = nullptr;
  {
    std::lock_guard lk(fb_mu_);
    for (const PixelRect& r : ev.pixels) {
      std::string why;
      if (!fb_.apply(r, &why)) {
        ++n_dropped_;
        if (n_fb_errors_++ < 20) log::warn("standard mode: rectangle {}x{} at {},{} not drawn: {}", r.w, r.h, r.x, r.y, why);
      }
      if (const char* n = fb_encoding_name(r.encoding)) name = n;
    }
  }
  if (name) {
    std::lock_guard lk(info_mu_);
    decoder_name_ = name;
  }
  ++n_frames_;
  last_frame_ms_ = now_ms();
  waiting_key_ = false;
  // ホストは1回の要求に1回分の変更で答えるので、すぐ次を要求する。
  send_control(rfb::build_fbu_request(true, 0, 0, static_cast<uint16_t>(canvas_w_.load()),
                                      static_cast<uint16_t>(canvas_h_.load())));
}

bool Session::take_fb_update(const std::function<void(const uint32_t* pixels, int width, int height,
                                                      const std::vector<FbRect>& dirty)>& draw) {
  std::lock_guard lk(fb_mu_);
  const std::vector<FbRect> dirty = fb_.take_dirty();
  if (dirty.empty() || fb_.width() <= 0 || fb_.height() <= 0) return false;
  draw(fb_.pixels(), fb_.width(), fb_.height(), dirty);
  return true;
}

void Session::fast_adopt_all() {
  for (auto& s : streams_) s->fast_adopt_until_ms = now_ms() + kFastAdoptWindowMs;
}

// 同じ鍵で0x1cを送り直す（受け入れられる）。ホストはエンコーダとメディアストリームを
// 新しいSSRCグループで始め直し、ビデオのスレッドがそのグループに乗り換える。
void Session::reoffer_media(const std::string& why) {
  std::optional<proto::Offers> offers;
  std::optional<proto::NegotiationKeys> keys;
  bool alt = false;
  {
    std::lock_guard lk(send_mu_);
    if (neg_) {
      offers = neg_->offers;
      keys = neg_->keys;
      alt = neg_->alt_session;
    }
  }
  if (!offers || !keys) return;
  send_control(proto::build_0x1c(offers->audio, offers->video, *keys, proto::random_uuid4(),
                                 {.alt_session = alt, .legacy_cursor = opt_.legacy_cursor,
                                  .video2_offer = offers->video2}));
  log::info("{}: media stream re-offered", why);
  fast_adopt_all();
  request_keyframe();
}

void Session::request_resolution(const rfb::VirtualDisplayParams& display,
                                 const std::optional<rfb::VirtualDisplayParams>& display2) {
  if (!alive_) return;
  // 2台目のディスプレイは、そのストリームがある限り残す。
  const bool two = streams_.size() > 1;
  const rfb::VirtualDisplayParams second = display2.value_or(opt_.display2.value_or(display));
  if (two) {
    log::info("requesting {}x{} @{}x and {}x{} @{}x virtual displays", display.width, display.height,
              display.hidpi_scale, second.width, second.height, second.hidpi_scale);
  } else {
    log::info("requesting a {}x{} @{}x virtual display", display.width, display.height, display.hidpi_scale);
  }
  send_control(rfb::build_virtual_display(display, two ? &second : nullptr));
  send_control(rfb::build_fbu_request(false));
  fast_adopt_all();
  request_keyframe();
}

void Session::set_encodings(const std::vector<int32_t>& encodings) {
  if (opt_.media || !alive_ || encodings.empty()) return;
  send_control(rfb::build_set_encodings(encodings));
  send_control(rfb::build_fbu_request(false, 0, 0, static_cast<uint16_t>(canvas_w_.load()),
                                      static_cast<uint16_t>(canvas_h_.load())));
  log::info("standard mode: encodings switched to {} first, full update requested", encodings.front());
}

void Session::send_control(const Bytes& msg) {
  std::lock_guard lk(send_mu_);
  if (!neg_ || !neg_->cipher) return;
  try {
    neg_->cipher->encrypt_and_send(neg_->sock, msg);
  } catch (const std::exception& e) {
    log::debug("control send: {}", e.what());
  }
}

// ── tx: キープアライブ、RTCPフィードバック ───────────────────────────────

void Session::send_rtcp(VideoStream& s, const Bytes& rtcp, bool also_video_port) {
  if (!s.srtcp) return;
  if (rtp_dump_ && s.index == 0) dump_packet(DumpKind::Tx, nullptr, 0, rtcp, Clock::now());
  const Bytes pkt = s.srtcp->protect(rtcp);
  sock_ctrl_.send_to(dest_, ctrl_port_, pkt);
  if (also_video_port || s.index > 0) s.sock.send_to(dest_, s.port, pkt);
}

// AVPFのFIRとPLIに加え、純正のビューアが送る旧形式のPT=192 FIRも送る。デーモンは
// 前者をよく無視するが、後者にはキーフレームで応える。
void Session::send_keyframe_request(VideoStream& s) {
  static uint8_t fir_seq = 0;
  std::vector<uint32_t> targets;
  {
    std::lock_guard lk(state_mu_);
    for (const auto& [ssrc, tile] : s.ssrc_to_tile) {
      // HEVC: Macはタイル0のSSRC（そのIDR）で全部の帯をリフレッシュする。
      if (!opt_.hevc || refresh_all_ssrcs_ || tile == 0) targets.push_back(ssrc);
    }
  }
  const bool all_kinds = !opt_.hevc;
  for (uint32_t t : targets) {
    Bytes fb;
    auto put = [&fb](const Bytes& b) { fb.insert(fb.end(), b.begin(), b.end()); };
    if (all_kinds || refresh_fir_) put(proto::rtcp::build_fir(s.our_ssrc, t, fir_seq++));
    if (all_kinds || refresh_pli_) put(proto::rtcp::build_pli(s.our_ssrc, t));
    if (all_kinds || refresh_legacy_) put(proto::rtcp::build_fir_legacy(t));
    if (!fb.empty()) send_rtcp(s, proto::rtcp::compound_with_rr(s.our_ssrc, fb));
  }
  ++n_kf_requests_;
  s.last_refresh_ms = now_ms();
  s.answer_seen = false;
  log::debug("video {}: keyframe requested", s.index);
}

void Session::send_ltr_ack(VideoStream& s, uint16_t donl) {
  if (!s.srtcp) return;
  const Bytes app = proto::rtcp::build_app_ltrp(s.our_ssrc, donl);
  if (rtp_dump_ && s.index == 0) dump_packet(DumpKind::Tx, nullptr, 0, app, Clock::now());
  s.sock.send_to(dest_, s.port, s.srtcp->protect(app));
  ++n_ltr_acks_;
}

// 1本のストリームのフィードバック。tickごとにreceiver report（kSrEveryTicksごとに
// 空のsender reportも）を送り、起こされるたびにNACKとキーフレーム要求を送る。
void Session::tx_stream(VideoStream& s, int tick, bool periodic) {
  std::vector<proto::rtcp::ReportBlock> blocks;
  std::map<uint32_t, std::set<uint16_t>> nacks;
  {
    std::lock_guard lk(state_mu_);
    for (const auto& [ssrc, tile] : s.ssrc_to_tile) {
      const auto it = s.seq.find(ssrc);
      blocks.push_back({.ssrc = ssrc,
                        .roc = it != s.seq.end() ? it->second.roc : 0,
                        .max_seq = it != s.seq.end() ? it->second.max_seq : uint16_t(0)});
    }
    nacks.swap(s.nack_pending);
  }
  if (periodic) {
    Bytes report = proto::rtcp::build_rr(s.our_ssrc, blocks);
    if (tick % kSrEveryTicks == 0) {
      Bytes sr = proto::rtcp::build_empty_sr(s.our_ssrc, unix_now());
      report.insert(report.begin(), sr.begin(), sr.end());
    }
    send_rtcp(s, report);
  }

  // NACKは両方のポートに送る。5900（Pythonクライアントが送る先）へのフィードバックで
  // ホストが再送するかは確かめていない。修復が起きているかは統計のdrop / late-packetの
  // カウンタでわかる。
  for (const auto& [ssrc, seqs] : nacks) {
    if (seqs.empty()) continue;
    send_rtcp(s,
              proto::rtcp::compound_with_rr(
                  s.our_ssrc, proto::rtcp::build_nack(s.our_ssrc, ssrc, std::vector<uint16_t>(seqs.begin(), seqs.end()))),
              /*also_video_port=*/true);
    if (n_nacks_++ < 20) {
      log::info("video {}: NACK for SSRC 0x{:08x}: {} packet(s) from seq {}", s.index, ssrc, seqs.size(), *seqs.begin());
    }
  }

  const int64_t t = now_ms(), lp = s.last_packet_ms, lf = s.last_frame_ms;
  const bool streaming = lp && t - lp < 1000;
  if (streaming && t - (lf ? lf : lp) > kStallMs && !s.keyframe_wanted) {
    log::warn("video {}: packets arrive but no picture for {} s; requesting a keyframe", s.index, kStallMs / 1000);
    s.keyframe_wanted = true;
  }
  // 画面が静止している間はエンコーダが送ってこないので、そのときの要求は無駄になる。
  // 最初の1回だけは必ず送る（AppleのH.264の開始時のまとまりにはIDRがない）。
  const bool idle = lp && t - lp > kIdleMs;
  // 新しいストリームに乗り換えた直後か、ピクチャを失ったとき。MacがまだIDRを
  // 送っている間は待つ。
  const bool held = t < s.refresh_not_before_ms;
  const bool right_now = !held && s.keyframe_now.exchange(false);
  if (s.keyframe_wanted && !held &&
      (right_now || ((s.first_kf_request || !idle) && Clock::now() - s.last_kf_request >= retry_interval()))) {
    send_keyframe_request(s);
    s.last_kf_request = Clock::now();
    s.first_kf_request = false;
  }
  bool d3d11va = false;
  if (!opt_.hevc) {  // 回避しているPOCの折り返しはH.264のもの
    std::lock_guard lk(info_mu_);
    d3d11va = s.decoder_name == "d3d11va";
  }
  if (s.frames_since_key >= kD3d11ReanchorFrames && Clock::now() - s.last_reanchor >= kReanchorMinInterval && d3d11va) {
    log::info("video {}: d3d11va re-anchor: {} frames since the last intra; requesting a fresh one", s.index,
              s.frames_since_key.load());
    send_keyframe_request(s);
    s.last_reanchor = Clock::now();
  }
}

// HEVCは早めに再要求する。応答は要求から約30 msで来て、応答が欠けたかはDONLで
// 見分けられる。H.264のキーフレームは大きな1枚のピクチャで、届くのにもっと時間が
// かかることがある。
std::chrono::milliseconds Session::retry_interval() const {
  return opt_.hevc ? kHevcRefreshRetry : kKeyframeRequestInterval;
}

void Session::tx_loop() {
  int tick = 0;
  int64_t next_reoffer = 0, reoffer_backoff = kReofferBackoffMinMs;
  SessionStats prev{};
  auto prev_t = Clock::now();
  auto next_tick = Clock::now();
  while (!stop_) {
    // 早く起こされたとき（損失、NACK）はフィードバックだけを送る。
    const bool periodic = Clock::now() >= next_tick;
    if (periodic) {
      ++tick;
      next_tick = Clock::now() + kTxInterval;
    }
    try {
      if (periodic) {
        if (audio_enc_) sock_ctrl_.send_to(dest_, ctrl_port_, audio_enc_->encrypt(kHeartbeatPayload, kAudioPt));
        // Screen Sharing.appやPythonクライアントと同じく、tickごとに最小の
        // インクリメンタルなFramebufferUpdateRequestを送る。デーモンは制御チャネルの
        // 送信を要求ごとに再開する。RFB経由でビデオを引き出さないよう1x1にする
        // （session.py、_maybe_poll_cursor）。
        send_control(rfb::build_fbu_request(true, 0, 0, 1, 1));
      }

      for (auto& s : streams_) tx_stream(*s, tick, periodic);

      // 制御チャネルが生きたまま、ホストのメディアセッションだけが終わることがある
      // （ディスプレイのスリープからロック画面に復帰するとそうなる）。UDPには何も
      // 来なくなり、入力しても戻らない。提示し直し、来ないままの間は間隔を広げていく。
      const int64_t t = now_ms();
      if (const int64_t lc = last_ctrl_rx_ms_; lc && periodic) {
        const int64_t silent_after = n_ctrl_other_ > 0 ? kMediaSilentMs : kMediaSilentNoAudioMs;
        if (t - lc <= silent_after) {
          reoffer_backoff = kReofferBackoffMinMs;
          next_reoffer = 0;
        } else if (t >= next_reoffer) {
          ++n_media_reoffers_;
          reoffer_media(std::format("no UDP from the Mac for {:.1f} s", (t - lc) / 1000.0));
          next_reoffer = t + reoffer_backoff;
          reoffer_backoff = std::min(reoffer_backoff * 2, kReofferBackoffMaxMs);
        }
      }

      if (periodic && tick % kStatsEveryTicks == 0) {
        const SessionStats s = stats();
        const double dt = std::chrono::duration<double>(Clock::now() - prev_t).count();
        log::info("stats: {:.0f} pkt/s {:.1f} Mbit/s, {:.1f} fps, lost {} (+{}), dropped {} (+{}), NACK {}, keyframe req {}, "
                  "queue drops {}, decoder {}{} | repaired {}, late after drop {}, other SSRCs {} pkt, rtcp rx ctrl {} "
                  "video {}, audio rx {}, tcp rx {} msgs (+{}), cursor {}, sent pointer {} (+{}) keys {} (+{}), "
                  "media re-offers {}, skipped pictures {}, LTR acks {}",
                  (s.video_packets - prev.video_packets) / dt, (s.video_bytes - prev.video_bytes) * 8 / dt / 1e6,
                  (s.frames_decoded - prev.frames_decoded) / dt, s.lost_packets, s.lost_packets - prev.lost_packets,
                  s.dropped_frames, s.dropped_frames - prev.dropped_frames, s.nacks_sent, s.keyframe_requests,
                  s.queue_drops, s.decoder, s.waiting_for_keyframe ? ", waiting for keyframe" : "",
                  s.repaired_frames, s.late_after_drop, s.unknown_ssrc_packets, s.ctrl_rtcp, s.video_rtcp, s.ctrl_other,
                  s.tcp_messages, s.tcp_messages - prev.tcp_messages, s.cursor_updates, s.pointer_events,
                  s.pointer_events - prev.pointer_events, s.key_events, s.key_events - prev.key_events,
                  n_media_reoffers_.load(), s.skipped_pictures, s.ltr_acks);
        if (opt_.perf) log::info("{}", perf_line());
        prev = s;
        prev_t = Clock::now();
      }
    } catch (const std::exception& e) {
      log::debug("tx tick: {}", e.what());
    }
    // まだ要るリフレッシュは、tickの合間でもretry_interval()後に再要求する。
    auto wait = std::chrono::duration_cast<std::chrono::milliseconds>(next_tick - Clock::now());
    for (const auto& s : streams_) {
      if (!s->keyframe_wanted) continue;
      wait = std::min(wait, retry_interval());
      if (const int64_t held = s->refresh_not_before_ms - now_ms(); held > 0) {
        wait = std::min(wait, std::chrono::milliseconds(held));
      }
    }
    std::unique_lock lk(tx_mu_);
    tx_cv_.wait_for(lk, std::max(wait, std::chrono::milliseconds(1)), [this] { return tx_wake_ || stop_.load(); });
    tx_wake_ = false;
  }
}

// ── 入力 ─────────────────────────────────────────────────────────────────

void Session::send_key(bool down, uint32_t keysym) {
  if (!keysym || !alive_) return;
  std::lock_guard lk(send_mu_);
  if (!neg_ || !neg_->cipher) return;
  try {
    neg_->cipher->encrypt_and_send(neg_->sock, rfb::build_key_event(down, keysym));
    ++n_keys_;
  } catch (const std::exception& e) {
    log::debug("key send: {}", e.what());
  }
}

void Session::send_pointer(uint8_t buttons, int x, int y) {
  if (!alive_) return;
  std::lock_guard lk(send_mu_);
  if (!neg_ || !neg_->cipher) return;
  const int cw = canvas_w_, ch = canvas_h_;
  const int w = cw > 0 ? cw : 65535, h = ch > 0 ? ch : 65535;
  x = std::clamp(x, 0, w - 1);
  y = std::clamp(y, 0, h - 1);
  // ISS_POINTER（ダブルクリックが効くまでの遅れを調べる実験）: "rfb"は素の0x05
  // PointerEvent。"time"は接続からのmsをバイト6..9に入れる。"clicks"はボタンを
  // 押している間と離したときに、クリック数（Windowsのダブルクリックの時間と距離で
  // 数える）をバイト2..5に入れる。
  uint32_t arg = 0, delta = 0;
  if (pointer_mode_ == PointerMode::Time) delta = static_cast<uint32_t>(now_ms() - pointer_t0_ms_);
  if (pointer_mode_ == PointerMode::Clicks) {
    const uint8_t pressed = buttons & ~pointer_prev_buttons_ & 7;
    if (pressed) {
      const int64_t t = now_ms();
      const bool again = pressed == pointer_last_button_ && t - pointer_last_down_ms_ <= GetDoubleClickTime() &&
                         std::abs(x - pointer_last_x_) <= GetSystemMetrics(SM_CXDOUBLECLK) / 2 &&
                         std::abs(y - pointer_last_y_) <= GetSystemMetrics(SM_CYDOUBLECLK) / 2;
      pointer_clicks_ = again ? pointer_clicks_ + 1 : 1;
      pointer_last_button_ = pressed;
      pointer_last_down_ms_ = t;
      pointer_last_x_ = x;
      pointer_last_y_ = y;
    }
    if ((buttons | pointer_prev_buttons_) & 7) arg = pointer_clicks_;
  }
  if (opt_.log_input && ((buttons ^ pointer_prev_buttons_) & 7)) {
    log::info("pointer sent: buttons 0x{:02x} at {},{} arg {} delta {}", buttons, x, y, arg, delta);
  }
  pointer_prev_buttons_ = buttons;
  try {
    neg_->cipher->encrypt_and_send(neg_->sock,
                                   pointer_mode_ == PointerMode::Rfb
                                       ? rfb::build_pointer_event(buttons, x, y)
                                       : build_msg10_pointer(neg_->cipher->cbc_key(), buttons, x, y, arg, delta));
    ++n_pointer_;
  } catch (const std::exception& e) {
    log::debug("pointer send: {}", e.what());
  }
}

void Session::request_keyframe() {
  for (auto& s : streams_) s->keyframe_wanted = true;
  wake_tx();
}

SessionStats Session::stats() const {
  SessionStats s;
  s.video_packets = n_packets_;
  s.video_bytes = n_bytes_;
  s.lost_packets = n_lost_;
  s.dropped_frames = n_dropped_;
  s.frames_decoded = n_frames_;
  s.nacks_sent = n_nacks_;
  s.keyframe_requests = n_kf_requests_;
  s.queue_drops = n_queue_drops_;
  s.unknown_ssrc_packets = n_unknown_;
  s.ctrl_rtcp = n_ctrl_rtcp_;
  s.ctrl_other = n_ctrl_other_;
  s.tcp_messages = n_tcp_msgs_;
  s.pointer_events = n_pointer_;
  s.key_events = n_keys_;
  s.late_after_drop = n_late_;
  s.cursor_updates = n_cursor_;
  s.video_rtcp = n_video_rtcp_;
  s.skipped_pictures = n_skipped_;
  s.ltr_acks = n_ltr_acks_;
  if (opt_.media) {
    s.waiting_for_keyframe = false;
    for (const auto& st : streams_) {
      s.repaired_frames += st->repaired;
      s.waiting_for_keyframe = s.waiting_for_keyframe || st->waiting_key;
    }
  } else {
    s.waiting_for_keyframe = waiting_key_;
  }
  std::lock_guard lk(info_mu_);
  s.decoder = opt_.media ? (streams_.empty() ? "-" : streams_[0]->decoder_name) : decoder_name_;
  return s;
}

}  // namespace iss::session
