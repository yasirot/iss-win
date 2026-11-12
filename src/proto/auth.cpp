#include "proto/auth.h"

#include <format>

#include "core/log.h"
#include "crypto/crypto.h"

namespace iss::proto {
namespace {

using crypto::BigUint;

// AppleのSRPの方式。RFC 5054の4096ビットの群、SHA-512、PBKDF2でのパスワードの
// 引き延ばし。
constexpr size_t kSrpHashLen = 64;          // SHA-512の出力長
constexpr size_t kSrpModulusLen = 512;      // 4096ビット / 8
constexpr size_t kSrpPbkdf2DkLen = 128;     // AppleのSASL srp.soに合わせる
constexpr uint64_t kSrpMaxIterations = 1'000'000;
constexpr size_t kNonSrpAesKeyLen = 16;
constexpr size_t kRsaModulusPayloadLen = 256;  // 2048ビットRSAの暗号ブロック長
constexpr size_t kNonSrpCredFieldLen = 64;     // 資格情報1つにつきARD形式の64バイトスロット
constexpr uint32_t kSrpC2s1Len = 650;
constexpr uint32_t kSrpC2s2Len = 1076;
// 長さ付きの認証パケットの上限。最大のもの（SRPチャレンジ）でも約1.2 KBなので、
// これに近い値が来たらサーバーが壊れているか悪意がある。
constexpr uint32_t kMaxAuthPacket = 64 * 1024;

Bytes recv_packet(net::TcpSocket& sock, const char* what) {
  const uint32_t len = rd_be32(sock.recv_exact(4).data());
  if (len > kMaxAuthPacket) throw AuthError(std::format("{}: implausible length {}", what, len));
  return sock.recv_exact(len);
}

Bytes sha512_of(const Bytes& a, const Bytes& b) { return crypto::sha512(ByteWriter().bytes(a).bytes(b).take()); }

// ── 共通の段階: RSA1の初期化 ──────────────────────────────────────────────

// 認証タイプ0x21と空のRSA1要求を送ると、サーバーはRSA公開鍵を返す。どちらの経路も
// ここから始まり、サーバーは続くc2s1を見てSRPかnon-SRPかを見分ける。
crypto::RsaPublicKey rsa1_init(net::TcpSocket& sock) {
  static constexpr uint8_t kInit[] = {0x21, 0x00, 0x00, 0x00, 0x0a, 0x01, 0x00, 'R',
                                      'S',  'A',  '1',  0x00, 0x00, 0x00, 0x00};
  sock.send_all(kInit, sizeof(kInit));
  Bytes pkt = recv_packet(sock, "RSA1 init");
  // 2バイトの方向プレフィックス、u32 BEのkeyLength、DERの公開鍵の順。
  Bytes der;
  try {
    ByteReader r(pkt);
    r.skip(2);
    der = r.take(r.be32());
  } catch (const std::out_of_range&) {
    throw AuthError(std::format("RSA1 init: truncated public key packet ({}B)", pkt.size()));
  }
  auto key = crypto::RsaPublicKey::from_der(der);
  log::info("RSA1 init: server pubkey {} bits", key.bits());
  return key;
}

// ── non-SRPの経路 ─────────────────────────────────────────────────────────

void send_nonsrp_credentials(net::TcpSocket& sock, const crypto::RsaPublicKey& server_pub,
                             const Bytes& aes_key, const std::string& username, const std::string& password) {
  Bytes creds = ByteWriter().bytes(pack_ard_credential(username)).bytes(pack_ard_credential(password)).take();
  const Bytes enc_creds = crypto::aes_ecb_encrypt(aes_key, creds);
  secure_wipe(creds);
  const Bytes enc_aes_key = server_pub.encrypt_pkcs1v15(aes_key);

  ByteWriter blob;
  blob.u8(0x01).u8(0x00).str("RSA1");
  blob.be16(1).bytes(enc_creds);
  blob.be16(1).bytes(enc_aes_key);
  ByteWriter msg;
  msg.be32(static_cast<uint32_t>(blob.size())).bytes(blob.data());
  sock.send_all(msg.data());
}

// 4バイトの詰め物（M2の位置）、続いてu32 BEの結果（0 = 成功）。
void read_nonsrp_result(net::TcpSocket& sock) {
  sock.recv_exact(4);
  const uint32_t result = rd_be32(sock.recv_exact(4).data());
  if (result != 0) throw AuthError(std::format("non-SRP auth rejected: result={}", result));
}

// ── SRPの経路 ─────────────────────────────────────────────────────────────

// c2s1では、RSAで暗号化したユーザー名を"modulus"の位置に入れる。サーバーはこれを
// 復号できたときだけSRPに進み、modulusが平文ならnon-SRPの経路に進む。
void send_srp_modulus(net::TcpSocket& sock, const crypto::RsaPublicKey& server_pub, const std::string& username) {
  ByteWriter inner;
  inner.be32(static_cast<uint32_t>(username.size())).str(username).zeros(3);
  ByteWriter payload;
  payload.be32(static_cast<uint32_t>(inner.size())).bytes(inner.data());
  const Bytes encrypted = server_pub.encrypt_pkcs1v15(payload.data());
  if (encrypted.size() != kRsaModulusPayloadLen) {
    throw AuthError(std::format("expected {}B RSA block, got {}", kRsaModulusPayloadLen, encrypted.size()));
  }

  ByteWriter c2s1(4 + kSrpC2s1Len);
  c2s1.be32(kSrpC2s1Len);
  c2s1.le16(1).str("RSA1").u8(0x00).u8(0x02);
  c2s1.be16(static_cast<uint16_t>(kRsaModulusPayloadLen)).bytes(encrypted);
  c2s1.zeros(384);
  sock.send_all(c2s1.data());
}

SrpChallenge read_srp_challenge(net::TcpSocket& sock) {
  Bytes s2c1 = recv_packet(sock, "SRP challenge");
  if (s2c1.size() < 1000) {
    throw AuthError(std::format("SRP challenge too short ({}B); server fell back to non-SRP path", s2c1.size()));
  }
  return parse_apple_srp_challenge(s2c1);
}

// c2s2の中身はA + M1 + capの折り返し + civ。サーバー側のパーサーが同じ処理で
// 読めるよう、c2s1と同じRSA1形式の包みに入れる。
void send_srp_proof(net::TcpSocket& sock, const SrpChallenge& ch, const SrpProof& proof) {
  const Bytes civ = crypto::random_bytes(16);
  ByteWriter sd;
  sd.be16(static_cast<uint16_t>(kSrpModulusLen)).bytes(proof.Ab);
  sd.u8(static_cast<uint8_t>(kSrpHashLen)).bytes(proof.M1);
  sd.be16(static_cast<uint16_t>(ch.cap.size())).bytes(ch.cap);
  sd.u8(16).bytes(civ);

  ByteWriter pay(4 + kSrpC2s2Len);
  pay.be32(kSrpC2s2Len);
  pay.le16(1).str("RSA1").u8(0x00).u8(0x02);
  pay.be16(static_cast<uint16_t>(sd.size() + 4)).be32(static_cast<uint32_t>(sd.size())).bytes(sd.data());
  if (pay.size() > 4 + kSrpC2s2Len) {
    throw AuthError(std::format("SRP proof does not fit in {}B (cap string is {}B)", kSrpC2s2Len, ch.cap.size()));
  }
  pay.zeros(4 + kSrpC2s2Len - pay.size());
  sock.send_all(pay.data());
}

// M2（サーバーがKを持つことの証明）は読むが検証しない。Pythonクライアントと同じで、
// 成否は結果のワードで決める。
void read_srp_result(net::TcpSocket& sock) {
  recv_packet(sock, "SRP M2");
  const uint32_t result = rd_be32(sock.recv_exact(4).data());
  if (result != 0) throw AuthError(std::format("SRP auth rejected: result={}", result));
}

std::string printable(const Bytes& b) {
  std::string s;
  for (uint8_t c : b) s.push_back(c >= 0x20 && c < 0x7F ? static_cast<char>(c) : '?');
  return s;
}

}  // namespace

Bytes pack_ard_credential(const std::string& value) {
  Bytes out(value.begin(), value.end());
  out.push_back(0);
  // 暗号ブロックから資格情報の長さがわからないよう、末尾を乱数で埋める。
  if (out.size() < kNonSrpCredFieldLen) {
    const Bytes pad = crypto::random_bytes(kNonSrpCredFieldLen - out.size());
    out.insert(out.end(), pad.begin(), pad.end());
  }
  out.resize(kNonSrpCredFieldLen);
  return out;
}

Bytes do_nonsrp_auth(net::TcpSocket& sock, const std::string& username, const std::string& password) {
  const crypto::RsaPublicKey server_pub = rsa1_init(sock);
  Bytes aes_key = crypto::random_bytes(kNonSrpAesKeyLen);
  send_nonsrp_credentials(sock, server_pub, aes_key, username, password);
  read_nonsrp_result(sock);
  log::info("AUTH OK (non-SRP)");
  return aes_key;  // enc1103のマスター鍵も兼ねる
}

// レイアウト（実際のScreen Sharing.appのハンドシェイクでは1165バイト）
//   0..11   TLVヘッダー（固定。読み飛ばす）
//   12      0x00（DERで正の整数を示す印）
//   13..524 N（512バイト）
//   u16 BE g_len, g
//   u8 salt_len, salt
//   u16 BE B_len, B
//   u64 BE iterations
//   u16 BE cap_len, cap
SrpChallenge parse_apple_srp_challenge(const Bytes& s2c1) {
  SrpChallenge ch;
  try {
    ByteReader r(s2c1);
    r.skip(12);
    if (const uint8_t z = r.u8(); z != 0) {
      throw AuthError(std::format("SRP parse: missing DER zero marker at offset 12, got {:#x}", z));
    }
    ch.Nb = r.take(kSrpModulusLen);
    const uint16_t g_len = r.be16();
    if (g_len == 0 || g_len > 4) throw AuthError(std::format("SRP parse: unsupported generator length {}", g_len));
    for (uint16_t i = 0; i < g_len; ++i) ch.g = (ch.g << 8) | r.u8();
    ch.salt = r.take(r.u8());
    ch.Bb = r.take(r.be16());
    ch.iterations = r.be64();
    ch.cap = r.take(r.be16());
  } catch (const std::out_of_range&) {
    throw AuthError(std::format("SRP challenge truncated ({}B)", s2c1.size()));
  }

  ch.N = BigUint::from_be(ch.Nb);
  ch.B = BigUint::from_be(ch.Bb);
  if (ch.N.bit_length() != kSrpModulusLen * 8 || !ch.N.is_odd()) {
    throw AuthError(std::format("expected an odd 4096-bit SRP modulus, got {} bits", ch.N.bit_length()));
  }
  if (ch.g < 2) throw AuthError(std::format("SRP generator {} is degenerate", ch.g));
  // SRP-6aでは、B % N == 0ならクライアントは中止しなければならない（S = 0になる）。
  if ((ch.B % ch.N).is_zero()) throw AuthError("SRP server ephemeral B is 0 mod N");
  // Appleが送ってくる反復回数は約10000〜150000。上限でPBKDF2の計算量を抑え、悪意の
  // あるサーバーがパスワードの引き延ばしでクライアントを止められないようにする。
  if (ch.iterations == 0 || ch.iterations > kSrpMaxIterations) {
    throw AuthError(std::format("SRP iteration count {} outside 1..1M", ch.iterations));
  }

  log::info("SRP challenge: N={}b g={} salt={}B iters={} cap={}", ch.Nb.size() * 8, ch.g, ch.salt.size(),
            ch.iterations, printable(ch.cap));
  return ch;
}

// 内側のハッシュには空のユーザー名を使う。ユーザー名はxではなくc2s1のmodulusの
// ペイロードで送るため（Appleの/usr/lib/sasl2/srp.soと、corecryptoの
// ccsrp_generate_xに合わせる）。
BigUint srp_derive_x(const Bytes& salt, uint64_t iterations, const std::string& password) {
  Bytes dk = crypto::pbkdf2_hmac_sha512(password, salt, iterations, kSrpPbkdf2DkLen);
  Bytes colon_dk = ByteWriter().u8(':').bytes(dk).take();
  secure_wipe(dk);
  Bytes inner = crypto::sha512(colon_dk);
  secure_wipe(colon_dk);
  BigUint x = BigUint::from_be(sha512_of(salt, inner));
  secure_wipe(inner);
  return x;
}

SrpProof srp_solve(const SrpChallenge& ch, const std::string& password, const Bytes& a_entropy) {
  const BigUint g(ch.g);
  const Bytes g_padded = g.to_be(kSrpModulusLen);

  // k = H(N || PAD(g))
  const BigUint k = BigUint::from_be(sha512_of(ch.Nb, g_padded));

  // aは[1, N-1]の範囲、A = g^a mod N。
  const BigUint a = BigUint::from_be(a_entropy) % (ch.N - BigUint(1)) + BigUint(1);
  SrpProof proof;
  proof.Ab = crypto::mod_exp(g, a, ch.N).to_be(kSrpModulusLen);

  // u = H(A || B)。xはsalt、反復回数、パスワードから求める。
  const BigUint u = BigUint::from_be(sha512_of(proof.Ab, ch.Bb));
  const BigUint x = srp_derive_x(ch.salt, ch.iterations, password) % ch.N;

  // S = (B - k*g^x)^(a + u*x) mod N。底は[0, N)に収めてから計算する。
  const BigUint kgx = crypto::mul_mod(k, crypto::mod_exp(g, x, ch.N), ch.N);
  const BigUint b = ch.B % ch.N;
  const BigUint base = compare(b, kgx) >= 0 ? b - kgx : b + ch.N - kgx;
  Bytes S = crypto::mod_exp(base, a + u * x, ch.N).to_be(kSrpModulusLen);
  proof.K = crypto::sha512(S);
  secure_wipe(S);

  // M1 = H(H(N) XOR H(g) || H("") || salt || A || B || K)。AppleのSASLの手順と
  // 同じく、H(I)は空のユーザー名から求める。
  Bytes h_ng = crypto::sha512(ch.Nb);
  const Bytes h_g = crypto::sha512(g_padded);
  for (size_t i = 0; i < h_ng.size(); ++i) h_ng[i] ^= h_g[i];
  static constexpr uint8_t kNone = 0;
  ByteWriter m1_in;
  m1_in.bytes(h_ng).bytes(crypto::sha512(&kNone, 0)).bytes(ch.salt).bytes(proof.Ab).bytes(ch.Bb).bytes(proof.K);
  proof.M1 = crypto::sha512(m1_in.data());
  return proof;
}

Bytes srp_master_key(const SrpProof& proof) {
  Bytes h = crypto::sha256(proof.K);
  h.resize(16);
  return h;
}

// SRPの後の通信は、enc1103がAES-CBCを準備するまで平文のまま。そのためcapの文字列が
// ChaCha20-Poly1305を示していても、返すのは16バイトのAES鍵になる。
Bytes do_srp_auth(net::TcpSocket& sock, const std::string& username, const std::string& password) {
  const crypto::RsaPublicKey server_pub = rsa1_init(sock);
  send_srp_modulus(sock, server_pub, username);
  const SrpChallenge ch = read_srp_challenge(sock);
  Bytes a_entropy = crypto::random_bytes(64);
  SrpProof proof = srp_solve(ch, password, a_entropy);
  secure_wipe(a_entropy);
  send_srp_proof(sock, ch, proof);
  read_srp_result(sock);
  log::info("AUTH OK (SRP)");
  Bytes key = srp_master_key(proof);
  secure_wipe(proof.K);
  return key;
}

}  // namespace iss::proto
