// 認証（SRP / non-SRP）、メディアのoffer + 0x1c、RTP → NALの組み立て直し。
// test_main.cppがテストの土台の後に読み込むので、TEST / CHECK / H()と
// RSAのテスト用の鍵（rsa_decrypt_for_test）が使える。
#include <winsock2.h>
#include <ws2tcpip.h>

#include <cstring>
#include <format>
#include <stdexcept>
#include <thread>

#include "media/nalu.h"
#include "net/tcp.h"
#include "net/udp.h"
#include "proto/auth.h"
#include "proto/check.h"
#include "proto/negotiation.h"
#include "proto/offers.h"
#include "proto/protobuf.h"

namespace {

std::string S(const char* hex) {
  Bytes b = H(hex);
  return std::string(b.begin(), b.end());
}

std::vector<Bytes> HL(const char* const* hex, size_t n) {
  std::vector<Bytes> out;
  for (size_t i = 0; i < n; ++i) out.push_back(H(hex[i]));
  return out;
}
#define HEXLIST(arr) HL(arr, std::size(arr))

void check_bytes_list(const std::vector<Bytes>& got, const std::vector<Bytes>& want) {
  CHECK(got.size() == want.size());
  for (size_t i = 0; i < got.size() && i < want.size(); ++i) CHECK_HEX(got[i], to_hex(want[i]));
}

Bytes sha512_empty() {
  static constexpr uint8_t kNone = 0;
  return crypto::sha512(&kNone, 0);
}

// ── 認証のやりとり用のループバックサーバー ───────────────────────────────

using ServerScript = std::function<void(SOCKET)>;

// 127.0.0.1（か::1）で接続を順に受け、それぞれで次のスクリプトを
// 別スレッドで動かす。CHECKはスレッドセーフでないので、スクリプトは
// 例外で失敗を伝え、テストはjoin()の結果（最初の失敗）を
// 調べる。
class LoopbackServer {
 public:
  explicit LoopbackServer(ServerScript script) : LoopbackServer(std::vector<ServerScript>{std::move(script)}) {}

  explicit LoopbackServer(std::vector<ServerScript> scripts, int family = AF_INET) {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    // セッションはこのポート番号と次の2つ（Macのメディアポート）でUDPをbindする。
    // 隣のUDPポートも空いているTCPポートを選ぶ。そうしないと、ほかのプログラムの
    // UDPソケットのせいでテストがときどき失敗する。
    for (int attempt = 0; attempt < 20 && !port_; ++attempt) {
      listen_ = ::socket(family, SOCK_STREAM, IPPROTO_TCP);
      sockaddr_in6 addr6{};
      addr6.sin6_family = AF_INET6;
      addr6.sin6_addr = in6addr_loopback;
      sockaddr_in addr4{};
      addr4.sin_family = AF_INET;
      addr4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
      sockaddr* addr = family == AF_INET6 ? reinterpret_cast<sockaddr*>(&addr6) : reinterpret_cast<sockaddr*>(&addr4);
      int len = family == AF_INET6 ? sizeof(addr6) : sizeof(addr4);
      if (::bind(listen_, addr, len) || ::listen(listen_, 1) || ::getsockname(listen_, addr, &len)) {
        throw std::runtime_error("loopback listen failed");
      }
      const uint16_t port = ntohs(family == AF_INET6 ? addr6.sin6_port : addr4.sin_port);
      bool udp_free = port <= 65533;
      try {
        for (uint16_t p = port; udp_free && p < port + 3; ++p) net::UdpSocket::bind(p);
      } catch (const net::NetError&) {
        udp_free = false;
      }
      if (udp_free) {
        port_ = port;
      } else {
        closesocket(listen_);
        listen_ = INVALID_SOCKET;
      }
    }
    if (!port_) throw std::runtime_error("no loopback port with free UDP neighbours");
    thread_ = std::thread([this, scripts = std::move(scripts)] {
      for (const ServerScript& script : scripts) {
        SOCKET c = ::accept(listen_, nullptr, nullptr);
        if (c == INVALID_SOCKET) {
          if (error_.empty()) error_ = "accept failed";
          return;
        }
        DWORD timeout_ms = 10000;
        setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));
        try {
          script(c);
        } catch (const std::exception& e) {
          if (error_.empty()) error_ = e.what();
        }
        closesocket(c);
      }
    });
  }
  ~LoopbackServer() {
    join();
    WSACleanup();
  }

  uint16_t port() const { return port_; }

  // スクリプトの終わりを待ち、その失敗を返す（通ったときは""）。recvで止まった
  // スクリプトが戻れるよう、先にクライアントのソケットを閉じておくこと。
  std::string join() {
    if (listen_ != INVALID_SOCKET) {
      closesocket(listen_);  // クライアントが接続しなかったときのaccept()の待ちを解く
      listen_ = INVALID_SOCKET;
    }
    if (thread_.joinable()) thread_.join();
    return error_;
  }

 private:
  SOCKET listen_ = INVALID_SOCKET;
  uint16_t port_ = 0;
  std::thread thread_;
  std::string error_;
};

void srv_send(SOCKET s, const Bytes& b) {
  size_t off = 0;
  while (off < b.size()) {
    int n = ::send(s, reinterpret_cast<const char*>(b.data() + off), static_cast<int>(b.size() - off), 0);
    if (n <= 0) throw std::runtime_error("server send failed");
    off += static_cast<size_t>(n);
  }
}

Bytes srv_recv(SOCKET s, size_t n) {
  Bytes out(n);
  size_t got = 0;
  while (got < n) {
    int r = ::recv(s, reinterpret_cast<char*>(out.data() + got), static_cast<int>(n - got), 0);
    if (r <= 0) throw std::runtime_error(std::format("server recv: wanted {}B, got {}B", n, got));
    got += static_cast<size_t>(r);
  }
  return out;
}

Bytes srv_recv_packet(SOCKET s) { return srv_recv(s, rd_be32(srv_recv(s, 4).data())); }

void srv_send_packet(SOCKET s, const Bytes& body) {
  srv_send(s, ByteWriter().be32(static_cast<uint32_t>(body.size())).bytes(body).take());
}

void expect(bool ok, const char* what) {
  if (!ok) throw std::runtime_error(std::format("server-side check failed: {}", what));
}

// 共通の最初の段階。15バイトのRSA1要求に、テスト用の鍵で答える。
void srv_rsa1_init(SOCKET s) {
  expect(srv_recv(s, 15) == H("210000000a01005253413100000000"), "RSA1 init request");
  const Bytes der = H(kRsaSpkiDer);
  srv_send_packet(s, ByteWriter().be16(1).be32(static_cast<uint32_t>(der.size())).bytes(der).take());
}

struct SrpServerResult {
  Bytes modulus_payload;  // RSAで復号したc2s1のペイロード
  Bytes cap_echo;
  bool m1_ok = false;
  Bytes key;  // サーバー側で導いたsha256(K)[:16]
};

// Pythonのベクタのverifierを使う、SRP-6aのサーバー側。S = (A * v^u)^b mod N。
// Kが一致すれば、クライアント側が最初から最後まで正しいと確かめられる。
void srp_server(SOCKET s, SrpServerResult& res) {
  using crypto::BigUint;
  srv_rsa1_init(s);

  const Bytes c2s1 = srv_recv_packet(s);
  expect(c2s1.size() == 650, "c2s1 is 650 bytes");
  expect(slice(c2s1, 0, 10) == H("01005253413100020100"), "c2s1 envelope");
  res.modulus_payload = rsa_decrypt_for_test(slice(c2s1, 10, 256));
  expect(slice(c2s1, 266, 384) == Bytes(384, 0), "c2s1 zero tail");

  const Bytes challenge = H(kSrpChallenge);
  srv_send_packet(s, challenge);

  const Bytes c2s2 = srv_recv_packet(s);
  expect(c2s2.size() == 1076, "c2s2 is 1076 bytes");
  ByteReader r(c2s2);
  expect(r.take(8) == H("0100525341310002"), "c2s2 envelope");
  const uint16_t outer_len = r.be16();
  const uint32_t sd_len = r.be32();
  expect(outer_len == sd_len + 4, "c2s2 length fields");
  expect(r.be16() == 512, "A length");
  const Bytes A = r.take(512);
  expect(r.u8() == 64, "M1 length");
  const Bytes m1 = r.take(64);
  res.cap_echo = r.take(r.be16());
  expect(r.u8() == 16, "civ length");
  r.skip(16);
  expect(r.pos() == 14 + sd_len, "sd length matches its contents");
  const Bytes tail = r.take(r.remaining());
  expect(tail == Bytes(tail.size(), 0), "c2s2 zero tail");

  const proto::SrpChallenge ch = proto::parse_apple_srp_challenge(challenge);
  const BigUint v = BigUint::from_be(H(kSrpVerifier)), b = BigUint::from_be(H(kSrpServerPriv));
  const BigUint u = BigUint::from_be(crypto::sha512(ByteWriter().bytes(A).bytes(ch.Bb).take()));
  const BigUint premaster =
      crypto::mod_exp(crypto::mul_mod(BigUint::from_be(A), crypto::mod_exp(v, u, ch.N), ch.N), b, ch.N);
  const Bytes K = crypto::sha512(premaster.to_be(512));

  Bytes h_ng = crypto::sha512(ch.Nb);
  const Bytes h_g = crypto::sha512(BigUint(ch.g).to_be(512));
  for (size_t i = 0; i < h_ng.size(); ++i) h_ng[i] ^= h_g[i];
  const Bytes want_m1 = crypto::sha512(
      ByteWriter().bytes(h_ng).bytes(sha512_empty()).bytes(ch.salt).bytes(A).bytes(ch.Bb).bytes(K).take());
  res.m1_ok = m1 == want_m1;

  const Bytes m2 = crypto::sha512(ByteWriter().bytes(A).bytes(m1).bytes(K).take());
  srv_send(s, ByteWriter().be32(64).bytes(m2).be32(res.m1_ok ? 0 : 1).take());
  res.key = slice(crypto::sha256(K), 0, 16);
}

// ── SRP ──────────────────────────────────────────────────────────────────

TEST(srp_challenge_parse) {
  const auto ch = proto::parse_apple_srp_challenge(H(kSrpChallenge));
  CHECK(ch.g == 5);
  CHECK(ch.iterations == static_cast<uint64_t>(kSrpIterations));
  CHECK_HEX(ch.salt, kSrpSalt);
  CHECK_HEX(ch.cap, kSrpCap);
  CHECK(ch.Nb.size() == 512 && ch.Bb.size() == 512);
  CHECK(ch.N.bit_length() == 4096);
}

TEST(srp_challenge_rejects_bad_input) {
  auto rejects = [](const Bytes& b) {
    try {
      proto::parse_apple_srp_challenge(b);
    } catch (const proto::AuthError&) {
      return true;
    }
    return false;
  };
  // ベクタの並びでのオフセット（saltは32バイト、Bは512バイト）。
  constexpr size_t kB = 563, kIters = kB + 512;
  const Bytes good = H(kSrpChallenge);
  CHECK(!rejects(good));
  CHECK(rejects(slice(good, 0, 600)));  // 途中で切れている
  Bytes marker = good;
  marker[12] = 1;
  CHECK(rejects(marker));
  Bytes iters = good;
  wr_be64(&iters[kIters], 1'000'001);
  CHECK(rejects(iters));
  wr_be64(&iters[kIters], 0);
  CHECK(rejects(iters));
  Bytes b_zero = good;
  std::fill(b_zero.begin() + kB, b_zero.begin() + kB + 512, uint8_t(0));
  CHECK(rejects(b_zero));
  Bytes b_is_n = good;
  std::copy(good.begin() + 13, good.begin() + 13 + 512, b_is_n.begin() + kB);  // B = N
  CHECK(rejects(b_is_n));
}

TEST(srp_derive_x_matches_python) {
  CHECK_HEX(proto::srp_derive_x(H(kSrpSalt), kSrpIterations, S(kSrpPassword)).to_be(64), kSrpX);
}

TEST(srp_solve_matches_python) {
  const auto ch = proto::parse_apple_srp_challenge(H(kSrpChallenge));
  const auto proof = proto::srp_solve(ch, S(kSrpPassword), H(kSrpAEntropy));
  CHECK_HEX(proof.Ab, kSrpA);
  CHECK_HEX(proof.M1, kSrpM1);
  CHECK_HEX(proof.K, kSrpK);
  CHECK_HEX(proto::srp_master_key(proof), kSrpMasterKey);
}

TEST(srp_auth_against_loopback_server) {
  SrpServerResult res;
  LoopbackServer server([&](SOCKET s) { srp_server(s, res); });
  Bytes key;
  {
    auto sock = net::TcpSocket::connect("127.0.0.1", server.port(), 5000);
    key = proto::do_srp_auth(sock, S(kSrpUsername), S(kSrpPassword));
  }
  const std::string err = server.join();
  CHECK(err.empty());
  if (!err.empty()) std::fprintf(stderr, "    server: %s\n", err.c_str());
  CHECK_HEX(res.modulus_payload, kSrpModulusPayload);
  CHECK_HEX(res.cap_echo, kSrpCap);
  CHECK(res.m1_ok);
  CHECK(key.size() == 16 && key == res.key);
}

TEST(srp_auth_wrong_password_is_rejected) {
  SrpServerResult res;
  LoopbackServer server([&](SOCKET s) { srp_server(s, res); });
  bool rejected = false;
  {
    auto sock = net::TcpSocket::connect("127.0.0.1", server.port(), 5000);
    try {
      proto::do_srp_auth(sock, S(kSrpUsername), "not the password");
    } catch (const proto::AuthError&) {
      rejected = true;
    }
  }
  CHECK(server.join().empty());
  CHECK(!res.m1_ok);
  CHECK(rejected);
}

TEST(srp_auth_short_challenge_means_fallback) {
  LoopbackServer server([](SOCKET s) {
    srv_rsa1_init(s);
    srv_recv_packet(s);                // c2s1
    srv_send_packet(s, Bytes(64, 0));  // non-SRPだけのサーバーが返すもの
  });
  bool rejected = false;
  {
    auto sock = net::TcpSocket::connect("127.0.0.1", server.port(), 5000);
    try {
      proto::do_srp_auth(sock, "viewer", "pw");
    } catch (const proto::AuthError&) {
      rejected = true;
    }
  }
  CHECK(server.join().empty());
  CHECK(rejected);
}

// ── non-SRP ──────────────────────────────────────────────────────────────

TEST(ard_credential_slot) {
  const Bytes a = proto::pack_ard_credential("me"), b = proto::pack_ard_credential("me");
  CHECK(a.size() == 64);
  CHECK(slice(a, 0, 3) == H("6d6500"));
  CHECK(slice(a, 3, 61) != slice(b, 3, 61));  // 末尾は乱数
  const Bytes full = proto::pack_ard_credential(std::string(70, 'p'));
  CHECK(full == Bytes(64, 'p'));  // 切り詰め、NULの入る余地はない
}

struct NonSrpServerResult {
  Bytes aes_key;
  std::string user, pass;
};

void nonsrp_server(SOCKET s, NonSrpServerResult& res, uint32_t result) {
  srv_rsa1_init(s);
  const Bytes blob = srv_recv_packet(s);
  expect(blob.size() == 394, "c2s1 is 394 bytes");
  expect(slice(blob, 0, 8) == H("0100525341310001"), "c2s1 envelope");
  expect(slice(blob, 136, 2) == H("0001"), "key slot marker");
  res.aes_key = rsa_decrypt_for_test(slice(blob, 138, 256));
  const Bytes creds = crypto::aes_ecb_decrypt(res.aes_key, slice(blob, 8, 128));
  auto cstr = [&](size_t off) {
    const char* p = reinterpret_cast<const char*>(creds.data() + off);
    return std::string(p, strnlen(p, 64));
  };
  res.user = cstr(0);
  res.pass = cstr(64);
  srv_send(s, ByteWriter().be32(0).be32(result).take());
}

TEST(nonsrp_auth_against_loopback_server) {
  NonSrpServerResult res;
  LoopbackServer server([&](SOCKET s) { nonsrp_server(s, res, 0); });
  Bytes key;
  {
    auto sock = net::TcpSocket::connect("127.0.0.1", server.port(), 5000);
    key = proto::do_nonsrp_auth(sock, S(kSrpUsername), S(kSrpPassword));
  }
  const std::string err = server.join();
  CHECK(err.empty());
  if (!err.empty()) std::fprintf(stderr, "    server: %s\n", err.c_str());
  CHECK(key.size() == 16 && key == res.aes_key);
  CHECK(res.user == S(kSrpUsername));
  CHECK(res.pass == S(kSrpPassword));
}

TEST(nonsrp_auth_rejection) {
  NonSrpServerResult res;
  LoopbackServer server([&](SOCKET s) { nonsrp_server(s, res, 1); });
  bool rejected = false;
  {
    auto sock = net::TcpSocket::connect("127.0.0.1", server.port(), 5000);
    try {
      proto::do_nonsrp_auth(sock, "viewer", "pw");
    } catch (const proto::AuthError&) {
      rejected = true;
    }
  }
  CHECK(server.join().empty());
  CHECK(rejected);
}

// ── メディアのoffer ─────────────────────────────────────────────────────────

TEST(offer_options) {
  proto::OfferOptions o;
  CHECK(o.client_name == S(kOfferClientName));
  CHECK(o.ltrp_enabled() && o.tiles() == 4);
  o.codec = proto::VideoCodec::Avc;
  CHECK(!o.ltrp_enabled() && o.tiles() == 1);
  o.ltrp = true;  // AVCでは有効にならない
  CHECK(!o.ltrp_enabled());
  o.codec = proto::VideoCodec::Hevc;
  o.ltrp = false;
  o.tiles_per_frame = 0;
  CHECK(!o.ltrp_enabled() && o.tiles() == 1);
}

TEST(offer_options_from_env) {
  _putenv_s("ISS_VIDEO_CODEC", "AVC");
  _putenv_s("ISS_LTRP", "0");
  _putenv_s("ISS_TILES_PER_FRAME", " 3 ");
  _putenv_s("ISS_AUDIO_F4", "6000");
  auto o = proto::OfferOptions::from_env();
  CHECK(o.codec == proto::VideoCodec::Avc);
  CHECK(o.ltrp == false);
  CHECK(o.tiles_per_frame == 3);
  CHECK(o.audio_f4 == 6000);
  _putenv_s("ISS_VIDEO_CODEC", "hevc");
  _putenv_s("ISS_TILES_PER_FRAME", "four");  // 解釈できない → 既定値
  o = proto::OfferOptions::from_env();
  CHECK(o.codec == proto::VideoCodec::Hevc);
  CHECK(!o.tiles_per_frame && o.tiles() == 4);
  for (const char* k : {"ISS_VIDEO_CODEC", "ISS_LTRP", "ISS_TILES_PER_FRAME", "ISS_AUDIO_F4"}) _putenv_s(k, "");
  o = proto::OfferOptions::from_env();
  CHECK(o.codec == proto::VideoCodec::Both && !o.ltrp && !o.tiles_per_frame && !o.audio_f4);
}

TEST(mediablob_matches_python) {
  const auto sid_v = static_cast<uint32_t>(kOfferSidVideo), sid_a = static_cast<uint32_t>(kOfferSidAudio);
  const auto ts = static_cast<uint64_t>(kOfferTimestamp);
  proto::OfferOptions both;
  CHECK_HEX(proto::build_mediablob(7, sid_v, ts, both), kBlobVideoBoth);
  proto::OfferOptions avc;
  avc.codec = proto::VideoCodec::Avc;
  CHECK_HEX(proto::build_mediablob(7, sid_v, ts, avc), kBlobVideoAvc);
  proto::OfferOptions hevc;
  hevc.codec = proto::VideoCodec::Hevc;
  hevc.ltrp = false;
  hevc.tiles_per_frame = 2;
  CHECK_HEX(proto::build_mediablob(7, sid_v, ts, hevc), kBlobVideoHevc);

  CHECK_HEX(proto::build_mediablob(8, sid_a, ts, both), kBlobAudioOn);
  proto::OfferOptions mute;
  mute.audio_enabled = false;
  CHECK_HEX(proto::build_mediablob(8, sid_a, ts, mute), kBlobAudioOff);
  proto::OfferOptions f4;
  f4.audio_f4 = 50000;
  CHECK_HEX(proto::build_mediablob(8, sid_a, ts, f4), kBlobAudioF4);

  bool threw = false;
  try { proto::build_mediablob(9, 0, 0, both); } catch (const std::invalid_argument&) { threw = true; }
  CHECK(threw);
}

TEST(remote_endpoint_info_matches_python) {
  proto::OfferOptions o;
  CHECK_HEX(proto::build_remote_endpoint_info(o), kRemoteEndpointInfo);
  o.hw_model = "Windows-" + std::string(200, 'X');  // 127バイトに切り詰める
  CHECK_HEX(proto::build_remote_endpoint_info(o), kRemoteEndpointInfoLong);
}

TEST(offer_plist_matches_python) {
  const Bytes rei = H(kRemoteEndpointInfo);
  CHECK_HEX(proto::build_offer_plist(7, H(kOfferBlobVideoZ), rei, S(kOfferCallId)), kOfferPlistVideo);
  CHECK_HEX(proto::build_offer_plist(8, H(kOfferBlobAudioZ), rei, S(kOfferCallId)), kOfferPlistAudio);
  CHECK(proto::extract_offer_ssrc(H(kOfferPlistVideo), true) == static_cast<uint32_t>(kOfferSidVideo));
  CHECK(proto::extract_offer_ssrc(H(kOfferPlistAudio), false) == static_cast<uint32_t>(kOfferSidAudio));
  CHECK(!proto::extract_offer_ssrc(H(kOfferPlistVideo), false));
  CHECK(!proto::extract_offer_ssrc(H("00112233"), true));
}

TEST(create_offers_roundtrip) {
  const proto::OfferOptions opt;
  const auto offers = proto::create_offers(opt);
  for (auto [p, mode] : {std::pair{&offers.video, 7}, std::pair{&offers.audio, 8}}) {
    auto root = plist::parse_binary(*p);
    CHECK(root.has_value());
    if (!root) continue;
    const plist::Value* m = root->get("avcMediaStreamNegotiatorMode");
    CHECK(m && m->i == mode);
    const plist::Value* id = root->get("avcMediaStreamOptionCallID");
    CHECK(id && id->s.size() == 36 && id->s[14] == '4');
    CHECK(id && id->s.find_first_not_of("0123456789ABCDEF-") == std::string::npos);
    const plist::Value* blob = root->get("avcMediaStreamNegotiatorMediaBlob");
    auto dec = blob ? zlib::decompress(blob->data) : std::nullopt;
    CHECK(dec.has_value());
    auto ssrc = proto::extract_offer_ssrc(*p, mode == 7);
    CHECK(ssrc.has_value());
    if (!dec || !ssrc) continue;
    // 取り出したセッションidとタイムスタンプから作り直すと、同じblobになる。
    uint64_t ts = 0;
    pb::for_each_field(dec->data(), dec->size(), [&](const pb::Field& f) {
      if (f.number == 13 && f.wire_type == 0) ts = f.varint;
    });
    CHECK(proto::build_mediablob(mode, *ssrc, ts, opt) == *dec);
  }
  CHECK(proto::create_offers(opt).video != offers.video);
}

TEST(canvas_dims_from_answer) {
  for (const char* msg : {kAnswerOdd, kAnswerEven}) {
    // Python版は奇数長のplistしか見つけない（kAnswerEvenではゼロになる）。
    const auto d = proto::extract_canvas_dims(H(msg));
    CHECK(d.width == 3840 && d.height == 2160 && d.tiles == 4);
    CHECK(d.ltrp == 1);
  }
  Bytes other_type = H(kAnswerOdd);
  other_type[0] = 0x1c;
  CHECK(!proto::extract_canvas_dims(other_type).valid());
  CHECK(!proto::extract_canvas_dims(H(kAnswerAudioOnly)).valid());
  CHECK(!proto::extract_canvas_dims(Bytes{}).valid());
}

// ── 0x1c ─────────────────────────────────────────────────────────────────

TEST(msg_0x1c_matches_python) {
  const proto::NegotiationKeys keys{H(kMsg1cKeys[0]), H(kMsg1cKeys[1]), H(kMsg1cKeys[2]), H(kMsg1cKeys[3])};
  std::array<uint8_t, 16> uuid{};
  const Bytes u = H(kMsg1cUuid);
  std::copy(u.begin(), u.end(), uuid.begin());
  const Bytes a = H(kOfferPlistAudio), v = H(kOfferPlistVideo);
  CHECK_HEX(proto::build_0x1c(a, v, keys, uuid, {}), kMsg1cDefault);
  CHECK_HEX(proto::build_0x1c(a, v, keys, uuid, {.legacy_cursor = true}), kMsg1cLegacyCursor);
  CHECK_HEX(proto::build_0x1c(a, v, keys, uuid, {.alt_session = true}), kMsg1cAltSession);

  proto::NegotiationKeys short_key = keys;
  short_key.video_key_s.pop_back();
  bool threw = false;
  try { proto::build_0x1c(a, v, short_key, uuid, {}); } catch (const std::invalid_argument&) { threw = true; }
  CHECK(threw);
}

TEST(negotiation_keys_and_uuid) {
  const auto k = proto::random_negotiation_keys();
  CHECK(k.audio_key_v.size() == 46 && k.audio_key_s.size() == 46);
  CHECK(k.video_key_v.size() == 46 && k.video_key_s.size() == 46);
  CHECK(k.video_key_v != k.video_key_s);

  std::array<uint8_t, 16> fixed{};
  const Bytes u = H(kMsg1cUuid);
  std::copy(u.begin(), u.end(), fixed.begin());
  CHECK(proto::uuid_to_upper_string(fixed) == S(kMsg1cUuidString));
  const auto r1 = proto::random_uuid4(), r2 = proto::random_uuid4();
  CHECK(r1 != r2);
  CHECK((r1[6] >> 4) == 4 && (r1[8] & 0xC0) == 0x80);
}

// ── ネゴシエーション ──────────────────────────────────────────────────────────

TEST(session_select_bodies) {
  Bytes want = H("0002000000000000616c6963650000");  // ヘッダ、cmd=0、"alice"、NUL、空のmachine
  want.resize(72);
  CHECK(proto::build_ss_cmd0_body("alice") == want);
  const Bytes long_name = proto::build_ss_cmd0_body(std::string(100, 'x'));
  CHECK(long_name.size() == 72 && slice(long_name, 8, 64) == Bytes(64, 'x'));

  const Bytes key = H("000102030405060708090a0b0c0d0e0f");
  const Bytes cmd2 = proto::build_ss_cmd2_body("bob", S(kSrpPassword), key);
  CHECK(cmd2.size() == 200);
  CHECK(slice(cmd2, 0, 8) == H("0002000000000200"));
  CHECK(slice(cmd2, 8, 64) == Bytes(64, 0));
  Bytes user = H("626f62");
  user.resize(64);
  CHECK(crypto::aes_ecb_decrypt(key, slice(cmd2, 0x48, 64)) == user);
  Bytes pass = H(kSrpPassword);
  pass.resize(64);
  CHECK(crypto::aes_ecb_decrypt(key, slice(cmd2, 0x88, 64)) == pass);

  bool threw = false;
  try { proto::build_ss_cmd2_body("bob", "pw", Bytes(8, 0)); } catch (const std::invalid_argument&) { threw = true; }
  CHECK(threw);
}

Bytes rfb_version() { return Bytes(rfb::kProtocolVersion, rfb::kProtocolVersion + 12); }

TEST(protocol_handshake_refusal) {
  LoopbackServer server([](SOCKET s) {
    srv_send(s, rfb_version());
    srv_recv(s, 12);
    const std::string reason = "Too many authentication failures";
    srv_send(s, ByteWriter().u8(0).be32(static_cast<uint32_t>(reason.size())).str(reason).take());
  });
  std::string what;
  {
    auto sock = net::TcpSocket::connect("127.0.0.1", server.port(), 5000);
    try {
      proto::do_protocol_handshake(sock);
    } catch (const proto::HandshakeError& e) {
      what = e.what();
    }
  }
  CHECK(server.join().empty());
  CHECK(what.find("Too many authentication failures") != std::string::npos);
}

// 答えと一緒に届くenc-1104のカーソル矩形の代わり。
Bytes fake_cursor_msg() { return ByteWriter().u8(0).u8(0).be16(1).zeros(8).be32(1104).zeros(16).take(); }

struct NegotiationServerResult {
  Bytes ecb_key;  // サーバー側で導いたもの
  Bytes ss_body;  // 問い合わせを送ったときのSessionSelectの返事
  Bytes msg_1c;
  std::unique_ptr<proto::StreamCipher> cipher;  // 続けてやりとりするための、サーバー側の暗号
};

// screensharingdの役でハンドシェイクを最後まで通す。SRP、ServerInit、
// `console_user` を名指しするSessionSelectの問い合わせ（空なら送らない）、
// toggleをまたいでレコードが切れる1103のバースト、本物の前に不完全な
// 0x1cの答えの順。`display` がnullなら、どんなVirtualDisplayでも、なくても
// 受け付ける（カーテンを使わない場合）。
void negotiation_server(SOCKET s, NegotiationServerResult& res, const std::string& console_user,
                        const rfb::VirtualDisplayParams* display) {
  srv_send(s, rfb_version());
  expect(srv_recv(s, 12) == rfb_version(), "client ProtocolVersion");
  srv_send(s, H("0121"));
  SrpServerResult srp;
  srp_server(s, srp);
  expect(srp.m1_ok, "SRP proof");
  res.ecb_key = srp.key;

  expect(srv_recv(s, 1) == H("c1"), "ClientInit shared flag");
  srv_send(s, ByteWriter().be16(2560).be16(1600).zeros(16).be32(3).str("mac").take());
  if (!console_user.empty()) {
    Bytes prompt = ByteWriter().be16(0x4a).be16(1).be32(0x5).zeros(4).str(console_user).take();
    prompt.resize(76);
    srv_send(s, prompt);
    res.ss_body = srv_recv(s, rd_be16(srv_recv(s, 2).data()));
    srv_send(s, H("00000000"));
  }
  const Bytes viewer_info = rfb::build_default_viewer_info_with_followup();
  expect(srv_recv(s, viewer_info.size()) == viewer_info, "ViewerInfo");
  if (display) {
    const Bytes vd = rfb::build_virtual_display(*display);
    expect(srv_recv(s, vd.size()) == vd, "VirtualDisplay");
  } else {
    // 長さはモード数だけで決まる。中身はクライアントの
    // モニタに合わせて変わる。
    const Bytes vd = rfb::build_virtual_display({});
    char first = 0;
    if (::recv(s, &first, 1, MSG_PEEK) == 1 && static_cast<uint8_t>(first) == vd[0]) {
      expect(srv_recv(s, vd.size())[0] == vd[0], "VirtualDisplay");
    }
  }
  const Bytes encodings = rfb::build_set_encodings();
  expect(srv_recv(s, encodings.size()) == encodings, "SetEncodings");

  // 鍵のblobは36バイトなら何でもよい。両端で同じCBCの鍵とIVを取り出せる。
  const Bytes blob = crypto::random_bytes(36);
  res.cipher = std::make_unique<proto::StreamCipher>(blob, res.ecb_key);
  proto::StreamCipher& srv = *res.cipher;
  const Bytes straddling = srv.encrypt_message(H("1400000000000000"));
  Bytes burst = ByteWriter()
                    .u8(0x14).zeros(7)  // 更新の前にUserSessionChanged
                    .u8(0).u8(0).be16(2)
                    .zeros(8).be32(1010).be16(2).be16(0x0102)
                    .zeros(8).be32(1103).bytes(blob)
                    .take();
  burst.insert(burst.end(), straddling.begin(), straddling.begin() + 10);
  srv_send(s, burst);
  expect(srv_recv(s, 8) == rfb::build_post_encryption_toggle(), "PostEncryptionToggle");
  srv_send(s, Bytes(straddling.begin() + 10, straddling.end()));

  auto recv_record = [&] {
    const Bytes ct = srv_recv(s, rd_be16(srv_recv(s, 2).data()));
    auto msg = srv.decrypt_message(ct.data(), ct.size());
    expect(msg.has_value(), "client record authenticates");
    return *msg;
  };
  expect(recv_record() == rfb::build_set_encodings(), "encrypted SetEncodings");
  res.msg_1c = recv_record();
  expect(recv_record() == rfb::build_fbu_request(false), "FramebufferUpdateRequest");

  Bytes degenerate = srv.encrypt_message(H(kAnswerAudioOnly));
  const Bytes cursor = srv.encrypt_message(fake_cursor_msg());
  degenerate.insert(degenerate.end(), cursor.begin(), cursor.end());
  srv_send(s, degenerate);
  expect(recv_record() == res.msg_1c, "re-query repeats the 0x1c");
  srv_send(s, srv.encrypt_message(H(kAnswerOdd)));
}

proto::ConnectOptions loopback_connect_options(uint16_t port) {
  proto::ConnectOptions opt;
  opt.host = "127.0.0.1";
  opt.port = port;
  opt.username = S(kSrpUsername);
  opt.password = S(kSrpPassword);
  opt.warmup = false;
  opt.offers = proto::Offers{H(kOfferPlistVideo), H(kOfferPlistAudio)};
  proto::HandshakeTiming& t = opt.timing;
  t.connect_timeout_ms = t.io_timeout_ms = 5000;
  t.post_viewer_info_ms = t.post_toggle_ms = t.requery_interval_ms = 0;
  t.burst_quiet_ms = t.drain_quiet_ms = 100;
  t.ss_peek_ms = t.ss_prompt_ms = 200;
  t.answer_timeout_ms = 2000;
  t.requery_limit = 2;
  return opt;
}

TEST(negotiate_against_loopback_server) {
  for (const std::string console_user : {"", "alice"}) {
    const rfb::VirtualDisplayParams display;
    NegotiationServerResult res;
    LoopbackServer server([&](SOCKET s) { negotiation_server(s, res, console_user, &display); });
    proto::ConnectOptions opt = loopback_connect_options(server.port());
    opt.display = display;
    std::string asked;
    opt.on_session_choice = [&](const std::string& user) {
      asked = user;
      return proto::SessionChoice::ShareConsole;
    };
    std::optional<proto::NegotiationResult> r;
    try {
      r = proto::connect_and_negotiate(opt);
    } catch (const std::exception& e) {
      std::fprintf(stderr, "    client: %s\n", e.what());
    }
    if (r) r->sock.close();
    const std::string err = server.join();
    CHECK(err.empty());
    if (!err.empty()) std::fprintf(stderr, "    server: %s\n", err.c_str());
    CHECK(r.has_value());
    if (!r) continue;

    CHECK(asked == console_user);
    CHECK(res.ss_body == (console_user.empty() ? Bytes{} : proto::build_ss_cmd0_body(console_user)));
    CHECK(r->server_width == 2560 && r->server_height == 1600);
    CHECK(r->ecb_key == res.ecb_key);
    CHECK(r->canvas.width == 3840 && r->canvas.height == 2160 && r->canvas.tiles == 4);
    CHECK(!r->alt_session);
    CHECK(r->rx_pending.empty());

    // サーバーが受けた0x1cには、セッションに渡した鍵が入っている。
    const Bytes& m = res.msg_1c;
    const size_t vo = m.size() > 0x80 ? 0x80 + rd_be16(&m[10]) : 0;
    CHECK(vo && m.size() >= vo + 0x5c);
    if (!vo || m.size() < vo + 0x5c) continue;
    CHECK(m[0] == 0x1c && slice(m, 6, 4) == H("00000007"));
    CHECK(slice(m, 0x24, 46) == r->keys.audio_key_v);
    CHECK(slice(m, vo + 0x2e, 46) == r->keys.video_key_s);

    auto leftover = [&](const Bytes& msg) {
      return std::find(r->leftover_msgs.begin(), r->leftover_msgs.end(), msg) != r->leftover_msgs.end();
    };
    CHECK(leftover(H(kAnswerAudioOnly)) && leftover(fake_cursor_msg()) && !leftover(H(kAnswerOdd)));
  }
}

// ── 接続チェック（iss-check.exe） ─────────────────────────────────────

// screensharingdが送るのと同じRFBの前置き。security type 33を示す。
void srv_preamble(SOCKET s) {
  srv_send(s, rfb_version());
  expect(srv_recv(s, 12) == rfb_version(), "client ProtocolVersion");
  srv_send(s, H("0121"));
}

proto::CheckOptions loopback_check_options(uint16_t port, const std::string& password) {
  proto::CheckOptions opt;
  opt.host = "127.0.0.1";
  opt.port = port;
  opt.username = S(kSrpUsername);
  opt.password = password;
  opt.connect_timeout_ms = opt.io_timeout_ms = 5000;
  return opt;
}

void check_server_ok(LoopbackServer& server) {
  const std::string err = server.join();
  CHECK(err.empty());
  if (!err.empty()) std::fprintf(stderr, "    server: %s\n", err.c_str());
}

using Outcome = proto::AuthAttempt::Outcome;

TEST(check_srp_accepted_then_hangs_up) {
  SrpServerResult srp;
  LoopbackServer server([&](SOCKET s) {
    srv_preamble(s);
    srp_server(s, srp);
    char b = 0;
    expect(::recv(s, &b, 1, 0) == 0, "client hangs up instead of sending ClientInit");
  });
  const proto::CheckResult r = proto::check_connection(loopback_check_options(server.port(), S(kSrpPassword)));
  check_server_ok(server);
  CHECK(srp.m1_ok);
  CHECK(r.ok());
  CHECK(r.accepted_mode() == proto::AuthMode::Srp);
  CHECK(r.attempts.size() == 1);
  CHECK(r.server_version == "RFB 003.889");
  CHECK(r.security_types == H("21"));
  CHECK(r.peer == std::format("127.0.0.1:{}", server.port()));
}

TEST(check_falls_back_on_a_fresh_tcp) {
  NonSrpServerResult nonsrp;
  LoopbackServer server(std::vector<ServerScript>{
      [](SOCKET s) {
        srv_preamble(s);
        srv_rsa1_init(s);
        srv_recv_packet(s);                // c2s1
        srv_send_packet(s, Bytes(64, 0));  // non-SRPだけのサーバーが返すもの
      },
      [&](SOCKET s) {
        srv_preamble(s);
        nonsrp_server(s, nonsrp, 0);
      }});
  const proto::CheckResult r = proto::check_connection(loopback_check_options(server.port(), S(kSrpPassword)));
  check_server_ok(server);
  CHECK(r.ok());
  CHECK(r.accepted_mode() == proto::AuthMode::NonSrp);
  CHECK(r.attempts.size() == 2 && r.attempts[0].outcome == Outcome::Rejected);
  CHECK(nonsrp.user == S(kSrpUsername) && nonsrp.pass == S(kSrpPassword));
}

TEST(check_nonsrp_first_when_asked) {
  NonSrpServerResult nonsrp;
  LoopbackServer server([&](SOCKET s) {
    srv_preamble(s);
    nonsrp_server(s, nonsrp, 0);
  });
  proto::CheckOptions opt = loopback_check_options(server.port(), S(kSrpPassword));
  opt.auth_mode = proto::AuthMode::NonSrp;
  const proto::CheckResult r = proto::check_connection(opt);
  check_server_ok(server);
  CHECK(r.ok() && r.accepted_mode() == proto::AuthMode::NonSrp && r.attempts.size() == 1);
}

TEST(check_wrong_password_is_a_rejection) {
  SrpServerResult srp;
  NonSrpServerResult nonsrp;
  LoopbackServer server(std::vector<ServerScript>{
      [&](SOCKET s) {
        srv_preamble(s);
        srp_server(s, srp);
      },
      [&](SOCKET s) {
        srv_preamble(s);
        nonsrp_server(s, nonsrp, 1);
      }});
  const proto::CheckResult r = proto::check_connection(loopback_check_options(server.port(), "not the password"));
  check_server_ok(server);
  CHECK(r.failed_stage == proto::CheckStage::Auth);
  CHECK(r.auth_rejected());
  CHECK(r.attempts.size() == 2);
  CHECK(r.error.find("result=1") != std::string::npos);
}

TEST(check_drop_mid_auth_is_not_a_rejection) {
  LoopbackServer server([](SOCKET s) {
    srv_preamble(s);
    srv_recv(s, 15);  // RSA1の初期要求を受けてから切る
  });
  const proto::CheckResult r = proto::check_connection(loopback_check_options(server.port(), S(kSrpPassword)));
  check_server_ok(server);
  CHECK(r.failed_stage == proto::CheckStage::Auth);
  CHECK(!r.auth_rejected());
  CHECK(r.attempts.size() == 1 && r.attempts[0].outcome == Outcome::Error);
}

TEST(check_reports_refusal_reason) {
  LoopbackServer server([](SOCKET s) {
    srv_send(s, rfb_version());
    srv_recv(s, 12);
    const std::string reason = "Too many authentication failures";
    srv_send(s, ByteWriter().u8(0).be32(static_cast<uint32_t>(reason.size())).str(reason).take());
  });
  const proto::CheckResult r = proto::check_connection(loopback_check_options(server.port(), S(kSrpPassword)));
  check_server_ok(server);
  CHECK(r.failed_stage == proto::CheckStage::Handshake);
  CHECK(r.error.find("Too many authentication failures") != std::string::npos);
  CHECK(r.attempts.empty());
}

TEST(check_non_rfb_service_fails_handshake) {
  LoopbackServer server([](SOCKET s) { srv_send(s, ByteWriter().str("HTTP/1.1 400").take()); });
  const proto::CheckResult r = proto::check_connection(loopback_check_options(server.port(), S(kSrpPassword)));
  check_server_ok(server);
  CHECK(r.failed_stage == proto::CheckStage::Handshake);
  CHECK(r.error.find("not an RFB server") != std::string::npos);
}

TEST(check_closed_port_fails_connect) {
  uint16_t port = 0;
  {
    LoopbackServer probe(std::vector<ServerScript>{});  // 空いたポートをbindし、何も受けない
    port = probe.port();
  }
  const proto::CheckResult r = proto::check_connection(loopback_check_options(port, S(kSrpPassword)));
  CHECK(r.failed_stage == proto::CheckStage::Connect);
  CHECK(r.attempts.empty() && r.server_version.empty());
}

// ── RTP → NALの組み立て直し ─────────────────────────────────────────────────

TEST(hevc_reassemble_matches_python) {
  check_bytes_list(media::hevc_reassemble_group(HEXLIST(kHevcGroupA)), HEXLIST(kHevcNalusA));
  CHECK(media::hevc_first_donl(HEXLIST(kHevcGroupA)) == static_cast<uint16_t>(kHevcDonlA));
  check_bytes_list(media::hevc_reassemble_group(HEXLIST(kHevcGroupB)), HEXLIST(kHevcNalusB));
  CHECK(media::hevc_first_donl(HEXLIST(kHevcGroupB)) == static_cast<uint16_t>(kHevcDonlB));
  CHECK(!media::hevc_first_donl({H("01")}));
}

TEST(avc_reassemble_matches_python) {
  check_bytes_list(media::avc_reassemble(HEXLIST(kAvcGroup)), HEXLIST(kAvcNalus));
}

// 2つ目のディスプレイのストリームは、SPS + PPS + スライスを1つのRFC 6184 STAP-Aで
// 送り、メインのストリームが付けるDONを付けない。
TEST(avc_reassemble_stap_a_without_don) {
  const Bytes sps = H("6742c01e"), pps = H("68ce3c80"), slice = H("2588840021");
  const Bytes stap = ByteWriter().u8(0x38).be16(4).bytes(sps).be16(4).bytes(pps).be16(5).bytes(slice).take();
  check_bytes_list(media::avc_reassemble({stap}), {sps, pps, slice});
  const Bytes with_don = ByteWriter().u8(0x38).be16(7).be16(4).bytes(sps).be16(4).bytes(pps).take();
  check_bytes_list(media::avc_reassemble({with_don}), {sps, pps});
}

TEST(avc_access_unit_flags_match_python) {
  for (size_t i = 0; i < std::size(kAvcAus); ++i) {
    const Bytes au = H(kAvcAus[i]);
    CHECK(media::avc_au_is_keyframe(au) == (kAvcAuKeyframe[i] != 0));
    CHECK(media::avc_au_has_sps(au) == (kAvcAuHasSps[i] != 0));
  }
}

TEST(avc_config_matches_python) {
  const Bytes cfg = H(kAvcConfig);
  const auto c = media::parse_avc_config(cfg);
  CHECK(c.has_value());
  if (c) {
    CHECK_HEX(c->sps, kAvcConfigSps);
    CHECK_HEX(c->pps, kAvcConfigPps);
  }
  CHECK(!media::parse_avc_config(slice(cfg, 0, cfg.size() - 12)));
  CHECK(!media::parse_avc_config(H("92000000")));
}

}  // namespace
