#include "proto/negotiation.h"

#include <algorithm>
#include <chrono>
#include <format>
#include <thread>
#include <tuple>
#include <utility>

#include "core/log.h"
#include "crypto/crypto.h"
#include "proto/auth.h"

namespace iss::proto {
namespace {

using Clock = std::chrono::steady_clock;

// 認証したユーザーがコンソールユーザーでないとき、デーモンがServerInitの後に付ける
// 76バイトのSessionSelect_SessionInfoの、body[0..3]。
constexpr uint8_t kSsMagic[4] = {0x00, 0x4a, 0x00, 0x01};
constexpr size_t kSsPromptLen = 76;
constexpr size_t kSsConsoleUserOff = 0x0c;
constexpr size_t kSsCmd0BodyLen = 72;
constexpr size_t kSsCmd2BodyLen = 200;
constexpr size_t kSsCredSlotLen = 64;  // body+0x48 / +0x88に置くAES-ECBの資格情報1つ分
constexpr uint32_t kMaxServerNameLen = 1 << 20;
constexpr uint32_t kMaxRefusalReasonLen = 64 * 1024;
constexpr size_t kRecvChunk = 65536;
// Pythonクライアントは0x1cの応答を、このバイト数を超えるまで読む。応答のplistだけで
// 数百バイトある。
constexpr size_t kAnswerMinBytes = 100;
// warmup_tcpは専用の短いタイムアウトを使う（rfb.py）。
constexpr int kWarmupConnectMs = 10000;
constexpr int kWarmupIoMs = 5000;

void sleep_ms(int ms) {
  if (ms > 0) std::this_thread::sleep_for(std::chrono::milliseconds(ms));
}

int ms_until(Clock::time_point deadline) {
  return static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now()).count());
}

std::string c_string(const uint8_t* p, size_t n) { return std::string(p, std::find(p, p + n, uint8_t(0))); }

bool has_ss_magic(const Bytes& b) { return b.size() >= 4 && std::equal(kSsMagic, kSsMagic + 4, b.begin()); }

// 平文でまとめて届いた応答から1103のエントリを探す。応答は、あれば0x14の
// UserSessionChanged通知が先に来て、次にFramebufferUpdateが来る。その矩形は
// 1010 / 1011（u16の長さ付きの本体）と1103（36バイトの鍵ブロブ）。ブロブと、
// そのupdateの直後のオフセットを返す。
struct Enc1103Entry {
  std::optional<Bytes> blob;
  size_t end = 0;
};

Enc1103Entry find_enc1103(const Bytes& init) {
  Enc1103Entry e;
  size_t pos = 0;
  while (pos < init.size()) {
    const uint8_t type = init[pos];
    if (type == rfb::SRV_USER_SESSION_CHANGED && pos + 8 <= init.size()) {
      pos += 8;
      continue;
    }
    if (type == rfb::SRV_FRAMEBUFFER_UPDATE && pos + 4 <= init.size()) {
      const uint16_t n_rects = rd_be16(&init[pos + 2]);
      size_t p = pos + 4;
      for (uint16_t i = 0; i < n_rects && p + 12 <= init.size(); ++i) {
        const auto enc = static_cast<int32_t>(rd_be32(&init[p + 8]));
        p += 12;
        if (enc == 1103 && p + 36 <= init.size()) {
          e.blob = Bytes(init.begin() + p, init.begin() + p + 36);
          p += 36;
        } else if ((enc == 1010 || enc == 1011) && p + 2 <= init.size()) {
          p += 2 + rd_be16(&init[p]);
        } else {
          break;
        }
      }
      pos = std::min(p, init.size());
    }
    break;
  }
  e.end = pos;
  return e;
}

bool peek_ss_prompt(net::TcpSocket& sock, int wait_ms) {
  try {
    auto peek = sock.recv_some(4, wait_ms, /*peek=*/true);
    return peek && has_ss_magic(*peek);
  } catch (const net::NetError&) {
    return false;
  }
}

// 届いているプロンプトから、読み捨てずにコンソールユーザー名を取り出す。
std::string peek_ss_console_user(net::TcpSocket& sock, int wait_ms) {
  try {
    auto peek = sock.recv_some(kSsPromptLen, wait_ms, /*peek=*/true);
    if (!peek || peek->size() <= kSsConsoleUserOff || !has_ss_magic(*peek)) return {};
    return c_string(peek->data() + kSsConsoleUserOff, peek->size() - kSsConsoleUserOff);
  } catch (const net::NetError&) {
    return {};
  }
}

struct SsPrompt {
  uint32_t flags = 0;  // ビットnが立っていればcmd=nを使える
  std::string console_user;
};

// プロンプトを読み取る。先にマジックをpeekで確かめるので、プロンプトがなければ
// 受信データはハンドシェイク用に残る（Pythonクライアントはこれを失う）。
std::optional<SsPrompt> read_ss_prompt(net::TcpSocket& sock, int wait_ms) {
  if (!peek_ss_prompt(sock, wait_ms)) return std::nullopt;
  const Bytes ssi = sock.recv_exact(kSsPromptLen);
  return SsPrompt{rd_be32(&ssi[4]), c_string(&ssi[kSsConsoleUserOff], kSsPromptLen - kSsConsoleUserOff)};
}

// pending + dataのうち、そろったレコードをすべて復号する。末尾の不完全なレコードは
// 次の読み込みのために`pending`に残す。（Pythonクライアントはこの末尾を捨てるので、
// レコードが2回の読み込みにまたがるとCBCの状態がずれる。）
std::vector<Bytes> decrypt_more(StreamCipher& cipher, Bytes& pending, const uint8_t* p, size_t n) {
  pending.insert(pending.end(), p, p + n);
  size_t used = 0;
  std::vector<Bytes> msgs = cipher.decrypt_stream(pending, &used);
  pending.erase(pending.begin(), pending.begin() + static_cast<std::ptrdiff_t>(used));
  return msgs;
}

// ソケットが`quiet_ms`の間なにも受け取らなくなるか、相手が閉じるまでに届いた
// データすべて。
Bytes recv_until_quiet(net::TcpSocket& sock, int quiet_ms) {
  Bytes out;
  while (auto chunk = sock.recv_some(kRecvChunk, quiet_ms)) {
    if (chunk->empty()) break;
    out.insert(out.end(), chunk->begin(), chunk->end());
  }
  return out;
}

// ── フェーズ1: TCP + 認証 ──────────────────────────────────────────────────

struct AuthedSocket {
  net::TcpSocket sock;
  Bytes ecb_key;  // 16バイトのenc1103マスター鍵
};

net::TcpSocket open_and_handshake(const ConnectOptions& opt) {
  net::TcpSocket sock = net::TcpSocket::connect(opt.host, opt.port, opt.timing.connect_timeout_ms);
  sock.set_timeout(opt.timing.io_timeout_ms);
  sock.set_nodelay(true);
  do_protocol_handshake(sock);
  return sock;
}

// 優先する認証を新しいTCPで行う。AuthErrorなら、もう一方の認証を別の新しいTCPで
// やり直す（デーモンは同じ接続での2回目の試行を受け付けない）。
AuthedSocket phase_auth(const ConnectOptions& opt) {
  using AuthFn = Bytes (*)(net::TcpSocket&, const std::string&, const std::string&);
  struct Method {
    AuthFn fn;
    const char* name;
  };
  const Method srp{do_srp_auth, "SRP"}, nonsrp{do_nonsrp_auth, "non-SRP"};
  const Method primary = opt.auth_mode == AuthMode::Srp ? srp : nonsrp;
  const Method fallback = opt.auth_mode == AuthMode::Srp ? nonsrp : srp;

  net::TcpSocket sock = open_and_handshake(opt);
  try {
    Bytes key = primary.fn(sock, opt.username, opt.password);
    return {std::move(sock), std::move(key)};
  } catch (const AuthError& e) {
    log::warn("{} auth failed ({}); falling back to {}", primary.name, e.what(), fallback.name);
  }
  sock.close();
  sock = open_and_handshake(opt);
  Bytes key = fallback.fn(sock, opt.username, opt.password);
  return {std::move(sock), std::move(key)};
}

// ── フェーズ2: ClientInit + ServerInit ─────────────────────────────────────

// sharedフラグ付きのClientInitを送り、ServerInit（24バイトのヘッダー + 名前）を受け取る。
struct ServerInit {
  int width = 0, height = 0;
  Bytes pixel_format;  // 16バイト
};

ServerInit phase_client_init(net::TcpSocket& sock) {
  static constexpr uint8_t kSharedFlag = 0xc1;
  sock.send_all(&kSharedFlag, 1);
  const Bytes head = sock.recv_exact(24);
  const uint32_t name_len = rd_be32(&head[20]);
  if (name_len > kMaxServerNameLen) throw HandshakeError(std::format("ServerInit: implausible name length {}", name_len));
  if (name_len) sock.recv_exact(name_len);
  ServerInit si{rd_be16(&head[0]), rd_be16(&head[2]), Bytes(head.begin() + 4, head.begin() + 20)};
  const uint8_t* pf = &head[4];
  log::info("ServerInit: {}x{}, pixel format {} bpp depth {} {}-endian {} max {}/{}/{} shift {}/{}/{}", si.width,
            si.height, pf[0], pf[1], pf[2] ? "big" : "little", pf[3] ? "true-colour" : "colour-map", rd_be16(pf + 4),
            rd_be16(pf + 6), rd_be16(pf + 8), pf[10], pf[11], pf[12]);
  return si;
}

// ── フェーズ2b: SessionSelect ──────────────────────────────────────────────

// プロンプトにcmd=0かcmd=2で答える。cmd=0はコンソールユーザーの画面を共有する
// （Macにポップアップが出て、相手が許可をクリックするまでブロックする）。cmd=2は
// ecb_keyで暗号化した資格情報で別セッションにログインする（ポップアップは出ない）。
void phase_session_select(net::TcpSocket& sock, bool alt_session, const ConnectOptions& opt, const Bytes& ecb_key) {
  const HandshakeTiming& t = opt.timing;
  const auto prompt = read_ss_prompt(sock, t.ss_prompt_ms);
  if (!prompt) {
    log::warn("session-select: no prompt — server may not be in session-select state "
              "(auth user matches console, or VNCSelectSession off)");
    return;
  }
  const int cmd = alt_session ? 2 : 0;
  log::info("session-select: prompt — flags={:#x} console_user='{}' mode={}", prompt->flags, prompt->console_user,
            alt_session ? "alt_session" : "share_console");
  if (!((prompt->flags >> cmd) & 1)) {
    log::warn("session-select: cmd={} not in flags mask {:#x}; daemon will likely reject", cmd, prompt->flags);
  }

  const Bytes body = alt_session ? build_ss_cmd2_body(opt.username, opt.password, ecb_key)
                                 : build_ss_cmd0_body(prompt->console_user);
  const Bytes msg = ByteWriter().be16(static_cast<uint16_t>(body.size())).bytes(body).take();
  sock.send_all(msg);
  log::info("session-select: sent cmd={} ({}B) — waiting up to {}s for ack", cmd, msg.size(), t.ss_ack_ms / 1000);

  const auto ack = sock.recv_some(kRecvChunk, t.ss_ack_ms);
  if (!ack) {
    throw HandshakeError(std::format(
        "session-select: timed out after {}s waiting for server ack — for cmd=0 the popup was likely never "
        "clicked, for cmd=2 the daemon rejected the creds",
        t.ss_ack_ms / 1000));
  }
  if (ack->empty()) {
    throw HandshakeError("session-select: server closed before responding — popup denied or daemon rejected the cmd");
  }
  log::info("session-select: ack received ({}B) — proceeding with normal post-toggle handshake", ack->size());
}

// ── フェーズ3: 平文のハンドシェイク + enc1103 ───────────────────────────────

// ViewerInfo（+ 続きの0x12）、VirtualDisplay、最初のSetEncodingsを送る。
// VirtualDisplayを送るとデーモンは仮想フレームバッファーのモードに入り、Macに
// カーテンをかける。送らなければ物理画面が流れてくる。alt-sessionでは別ユーザーの
// ログインを示すヒントを付けて必ず送り、コンソールユーザーにはカーテンをかけない。
void phase_handshake_plaintext(net::TcpSocket& sock, const ConnectOptions& opt, bool alt_session) {
  sock.send_all(rfb::build_default_viewer_info_with_followup());
  sleep_ms(opt.timing.post_viewer_info_ms);

  const rfb::VirtualDisplayParams* second = opt.display2 ? &*opt.display2 : nullptr;
  if (alt_session) {
    rfb::VirtualDisplayParams display = opt.display;
    display.alt_user_login = true;
    sock.send_all(rfb::build_virtual_display(display, second));
  } else if (opt.curtain) {
    sock.send_all(rfb::build_virtual_display(opt.display, second));
  } else {
    log::info("curtain=off — skipping SetDisplayConfiguration; host's physical screen will mirror the stream");
  }
  sock.send_all(rfb::build_set_encodings());
}

// まとめて届く応答を読む。最初の1バイトをenc1103_wait_msまで待ち、その後は
// burst_quiet_msの間なにも来なくなるまで読む。
Bytes read_reply_burst(net::TcpSocket& sock, const HandshakeTiming& t) {
  Bytes init;
  const auto deadline = Clock::now() + std::chrono::milliseconds(t.enc1103_wait_ms);
  for (int left; (left = ms_until(deadline)) > 0;) {
    auto chunk = sock.recv_some(kRecvChunk, std::min(left, t.burst_quiet_ms));
    if (!chunk) {
      if (!init.empty()) break;
      continue;
    }
    if (chunk->empty()) break;
    init.insert(init.end(), chunk->begin(), chunk->end());
  }
  return init;
}

// 1103のエントリからcipherを作り、PostEncryptionToggleを送る。受信側の状態を
// サーバーとそろえるため、その後に届くものを読み切る。途中で復号したメッセージは
// Pythonクライアントと同じく捨てる。
std::unique_ptr<StreamCipher> phase_enable_enc1103(net::TcpSocket& sock, const Bytes& ecb_key,
                                                   const HandshakeTiming& t, Bytes& pending) {
  const Bytes init = read_reply_burst(sock, t);
  const Enc1103Entry e = find_enc1103(init);
  if (!e.blob) {
    throw HandshakeError(
        "server did not advertise enc1103. Most often this is rate-limiting on the server — wait 10-15 "
        "seconds and retry.");
  }
  auto cipher = std::make_unique<StreamCipher>(*e.blob, ecb_key);
  log::info("enc1103 OK");

  size_t dropped = decrypt_more(*cipher, pending, init.data() + e.end, init.size() - e.end).size();
  sock.send_all(rfb::build_post_encryption_toggle());
  sleep_ms(t.post_toggle_ms);
  const Bytes drained = recv_until_quiet(sock, t.drain_quiet_ms);
  dropped += decrypt_more(*cipher, pending, drained.data(), drained.size()).size();
  if (dropped) log::debug("enc1103: dropped {} pre-offer message(s)", dropped);
  return cipher;
}

// ── フェーズ4: 暗号化したメディアのofferと応答 ──────────────────────────────

// kAnswerMinBytesを超えて受け取る（かつ途中で切れたレコードがない）か、
// answer_timeout_msの間データが来なくなるまで読む。キャンバスを含む最初の
// メッセージを応答とし、それ以外はRXループのために`leftover`へ入れる。
// 結果が無効なら、エンコーダーの準備がまだできていない。
CanvasDims read_video_answer(net::TcpSocket& sock, StreamCipher& cipher, Bytes& pending,
                             std::vector<Bytes>& leftover, const HandshakeTiming& t) {
  CanvasDims canvas;
  size_t got = 0;
  while (auto chunk = sock.recv_some(kRecvChunk, t.answer_timeout_ms)) {
    if (chunk->empty()) break;
    got += chunk->size();
    for (Bytes& msg : decrypt_more(cipher, pending, chunk->data(), chunk->size())) {
      log::debug("0x1c answer msg cmd={:#04x} len={}", msg.empty() ? 0 : msg[0], msg.size());
      if (!canvas.valid()) {
        if (const CanvasDims d = extract_canvas_dims(msg); d.valid()) {
          log::info("encoder canvas: {}x{} ({} tiles)", d.width, d.height, d.tiles);
          const std::vector<CanvasDims> all = extract_all_canvas_dims(msg.data(), msg.size());
          for (size_t i = 1; i < all.size(); ++i) {
            log::info("encoder canvas {}: {}x{} ({} tiles)", i + 1, all[i].width, all[i].height, all[i].tiles);
          }
          canvas = d;
          continue;
        }
      }
      leftover.push_back(std::move(msg));
    }
    if (got > kAnswerMinBytes && pending.empty()) break;
  }
  return canvas;
}

struct MediaAnswer {
  NegotiationKeys keys;
  CanvasDims canvas;
};

// 暗号化したSetEncodings、0x1cのoffer、FramebufferUpdateRequestを送り、応答を
// 受け取る。エンコーダーがまだ準備中の間（Mac側でagentが切り替わった直後によく
// ある）は、つなぎ直さずに同じTCPで同じ0x1cを送り直す。
MediaAnswer phase_media_offer(net::TcpSocket& sock, StreamCipher& cipher, const Offers& offers,
                              const ConnectOptions& opt, bool alt_session, Bytes& pending,
                              std::vector<Bytes>& leftover) {
  const HandshakeTiming& t = opt.timing;
  cipher.encrypt_and_send(sock, rfb::build_set_encodings());

  MediaAnswer out{random_negotiation_keys(), {}};
  const Bytes msg_1c = build_0x1c(offers.audio, offers.video, out.keys, random_uuid4(),
                                  {.alt_session = alt_session, .legacy_cursor = opt.legacy_cursor,
                                   .video2_offer = offers.video2});
  cipher.encrypt_and_send(sock, msg_1c);
  log::info("0x1c sent (encrypted){}", offers.video2.empty() ? "" : " with a second video stream");

  // デーモンにTCP側のpseudo-encodingの送信を始めさせ、enc-1104のカーソル矩形が
  // 届くようにする。
  if (!opt.legacy_cursor) {
    try {
      cipher.encrypt_and_send(sock, rfb::build_fbu_request(false));
      log::info("msg 0x03 FBU request sent (cursor pseudo-encoding poll)");
    } catch (const net::NetError& e) {
      log::warn("msg 0x03 send failed: {}", e.what());
    }
  }

  out.canvas = read_video_answer(sock, cipher, pending, leftover, t);
  for (int attempt = 1; !out.canvas.valid() && attempt <= t.requery_limit; ++attempt) {
    sleep_ms(t.requery_interval_ms);
    try {
      cipher.encrypt_and_send(sock, msg_1c);
    } catch (const net::NetError& e) {
      log::warn("0x1c re-query send failed: {}", e.what());
      break;
    }
    log::info("0x1c re-query {}/{} (degenerate canvas)", attempt, t.requery_limit);
    out.canvas = read_video_answer(sock, cipher, pending, leftover, t);
  }
  if (!out.canvas.valid()) log::warn("encoder canvas never became ready");
  return out;
}

// 標準モード。使うエンコーディング、画面全体の更新要求、AutoFrameBufferUpdateを
// 送る。その後はホストが変更分を自分から送ってくる（§9.1の手順15〜16）。届いた
// データはセッションのRXループが読む。
void phase_framebuffer_start(net::TcpSocket& sock, StreamCipher& cipher, const ConnectOptions& opt, int width,
                             int height) {
  cipher.encrypt_and_send(sock, opt.encodings.empty() ? rfb::build_set_encodings()
                                                      : rfb::build_set_encodings(opt.encodings));
  const auto w = static_cast<uint16_t>(width), h = static_cast<uint16_t>(height);
  cipher.encrypt_and_send(sock, rfb::build_fbu_request(false, 0, 0, w, h));
  cipher.encrypt_and_send(sock, rfb::build_auto_fbu(0, 0, w, h));
  std::string encs;
  for (int32_t e : opt.encodings) encs += std::format("{}{}", encs.empty() ? "" : ",", e);
  log::info("standard mode: framebuffer updates requested (encodings {})", encs.empty() ? "HP list" : encs);
}

}  // namespace

// ── 公開関数 ───────────────────────────────────────────────────────────────

Bytes do_protocol_handshake(net::TcpSocket& sock, std::string* server_version) {
  const Bytes banner = sock.recv_exact(12);  // サーバーのProtocolVersion
  if (!std::equal(banner.begin(), banner.begin() + 4, "RFB ")) {
    throw HandshakeError(std::format("not an RFB server (banner {})", to_hex(banner)));
  }
  if (server_version) {
    *server_version = std::string(banner.begin(), banner.end());
    if (server_version->back() == '\n') server_version->pop_back();
  }
  sock.send_all(reinterpret_cast<const uint8_t*>(rfb::kProtocolVersion), sizeof(rfb::kProtocolVersion) - 1);
  const uint8_t n_types = sock.recv_exact(1)[0];
  if (n_types == 0) {
    // RFC 6143 §7.1.2。セキュリティタイプが0個なら、続けてu32の長さと理由が来る。
    const uint32_t len = rd_be32(sock.recv_exact(4).data());
    if (len > kMaxRefusalReasonLen) throw HandshakeError("server refused the connection");
    const Bytes reason = sock.recv_exact(len);
    throw HandshakeError(std::format("server refused the connection: {}", std::string(reason.begin(), reason.end())));
  }
  return sock.recv_exact(n_types);
}

void warmup_tcp(const std::string& host, uint16_t port, const HandshakeTiming& timing) {
  net::TcpSocket sock = net::TcpSocket::connect(host, port, kWarmupConnectMs);
  sock.set_timeout(kWarmupIoMs);
  do_protocol_handshake(sock);
  sock.shutdown();
  sock.close();
  // Screen Sharing.appは本番のTCPの前に約1.4秒待ち、デーモンがセッションを登録し
  // 終えるようにしている。
  sleep_ms(timing.warmup_dwell_ms);
}

// レイアウト（72バイト）
//   +0..1  u16 BE  version = 2
//   +2..5          予約
//   +6     u8      cmd = 0
//   +7     u8      パディング
//   +8             コンソールユーザー名、NUL、マシン名（空）、NUL。残りは0埋め
// 本体に収まらない長さの名前は終端なしで切り詰める。Python版と同じ。
Bytes build_ss_cmd0_body(const std::string& console_user) {
  ByteWriter w(kSsCmd0BodyLen);
  w.be16(2).be16(0).zeros(2);
  w.u8(0).u8(0);
  w.str(console_user).u8(0);
  w.u8(0);
  Bytes body = w.take();
  body.resize(kSsCmd0BodyLen);
  return body;
}

// レイアウト（200バイト）。cmd=0と同じヘッダーでcmd = 2にし、+0x48まで0で埋め、
// 続けてユーザー名（+0x48）とパスワード（+0x88）を置く。どちらもUTF-8で、0埋めした
// 64バイトのスロットに入れてAES-128-ECB(ecb_key)で暗号化する。デーモンはこれを
// 復号してユーザーをログインさせ、loginwindowを飛ばす。
Bytes build_ss_cmd2_body(const std::string& username, const std::string& password, const Bytes& ecb_key) {
  if (ecb_key.size() != 16) throw std::invalid_argument("SessionSelect cmd=2: ecb_key must be 16 bytes");
  auto seal = [&](const std::string& s) {
    Bytes slot(kSsCredSlotLen, 0);
    std::copy_n(s.begin(), std::min(s.size(), slot.size()), slot.begin());
    Bytes ct = crypto::aes_ecb_encrypt(ecb_key, slot);
    secure_wipe(slot);
    return ct;
  };
  ByteWriter w(kSsCmd2BodyLen);
  w.be16(2).be16(0).zeros(2);
  w.u8(2).u8(0);
  w.zeros(0x48 - w.size());
  w.bytes(seal(username));
  w.bytes(seal(password));
  return w.take();
}

NegotiationResult connect_and_negotiate(const ConnectOptions& opt) {
  if (opt.share_console && opt.alt_session) {
    throw std::invalid_argument("share_console and alt_session are mutually exclusive");
  }
  const HandshakeTiming& t = opt.timing;
  NegotiationResult r;
  r.offers = opt.offers ? *opt.offers : create_offers(OfferOptions::from_env());

  if (opt.warmup) warmup_tcp(opt.host, opt.port, t);

  AuthedSocket conn = phase_auth(opt);
  ServerInit si = phase_client_init(conn.sock);

  // デーモンがServerInitの後にSessionSelectのプロンプトを付けるのは、認証した
  // ユーザー以外がMacにログインしているときだけ。だからプロンプトの有無でモードを
  // 決める。なければpeekしたバイトは受信キューに残る。
  bool alt_session = opt.alt_session;
  if (peek_ss_prompt(conn.sock, t.ss_peek_ms)) {
    if (!opt.alt_session && !opt.share_console && opt.on_session_choice) {
      const std::string console_user = peek_ss_console_user(conn.sock, t.ss_peek_ms);
      SessionChoice choice = SessionChoice::ShareConsole;
      try {
        choice = opt.on_session_choice(console_user);
      } catch (const std::exception& e) {
        log::error("session-choice prompt failed ({}); defaulting to share", e.what());
      }
      alt_session = choice == SessionChoice::AltSession;
      log::info("session-select: '{}' chose {}", console_user, alt_session ? "alt_session" : "share_console");
    }
    // Screen Sharing.appはcmd=2を、2本目のTCPでSRPをやり直してから送る。こうすると
    // デーモンがconn1の暗号器を持ったままにならない（持ったままだとコンソール
    // ユーザーにカーテンがかからず、ディスプレイの振り分けもおかしくなる）。cmd=0は
    // 暗号化した資格情報を送らないので、TCPは1本のまま。
    if (alt_session) {
      log::info("alt-session: closing conn1, opening conn2 for cmd=2");
      conn.sock.close();
      secure_wipe(conn.ecb_key);
      conn = phase_auth(opt);
      si = phase_client_init(conn.sock);
    }
    phase_session_select(conn.sock, alt_session, opt, conn.ecb_key);
  }

  phase_handshake_plaintext(conn.sock, opt, alt_session);
  r.cipher = phase_enable_enc1103(conn.sock, conn.ecb_key, t, r.rx_pending);
  if (opt.media) {
    MediaAnswer answer =
        phase_media_offer(conn.sock, *r.cipher, r.offers, opt, alt_session, r.rx_pending, r.leftover_msgs);
    r.keys = std::move(answer.keys);
    r.canvas = answer.canvas;
  } else {
    phase_framebuffer_start(conn.sock, *r.cipher, opt, si.width, si.height);
  }

  r.sock = std::move(conn.sock);
  r.ecb_key = std::move(conn.ecb_key);
  r.server_width = si.width;
  r.server_height = si.height;
  r.server_pixel_format = std::move(si.pixel_format);
  r.alt_session = alt_session;
  return r;
}

}  // namespace iss::proto
