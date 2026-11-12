// AppleのscreensharingdとのRFB認証（auth.pyの移植）。
// SRP-RFC5054-4096-SHA512-PBKDF2（macOS 15以降）と、従来のRSA1+AESの経路がある。
// どちらもenc1103を解くための16バイトの鍵を返す。
#pragma once

#include <stdexcept>
#include <string>

#include "core/bytes.h"
#include "crypto/bigint.h"
#include "net/tcp.h"

namespace iss::proto {

class AuthError : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

Bytes do_srp_auth(net::TcpSocket& sock, const std::string& username, const std::string& password);
Bytes do_nonsrp_auth(net::TcpSocket& sock, const std::string& username, const std::string& password);

// ── 内部処理（テスト用に公開） ─────────────────────────────────────────

struct SrpChallenge {
  crypto::BigUint N;
  Bytes Nb;  // N。512バイトのビッグエンディアン
  uint32_t g = 0;
  Bytes salt;
  crypto::BigUint B;
  Bytes Bb;
  uint64_t iterations = 0;
  Bytes cap;  // 例 "mda=SHA-512,replay_detection,..."
};

struct SrpProof {
  Bytes Ab;  // A。512バイトのビッグエンディアン
  Bytes M1;
  Bytes K;   // SHA-512(S)
};

SrpChallenge parse_apple_srp_challenge(const Bytes& s2c1);
// x = SHA512(salt || SHA512(":" || PBKDF2-HMAC-SHA512(password, salt, iters, 128)))
crypto::BigUint srp_derive_x(const Bytes& salt, uint64_t iterations, const std::string& password);
// `a_entropy`（64バイト）はos.urandom(64)の代わり。テストで一時鍵を固定できるようにするため。
SrpProof srp_solve(const SrpChallenge& ch, const std::string& password, const Bytes& a_entropy);
// enc1103のマスター鍵。SHA256(K)[:16]
Bytes srp_master_key(const SrpProof& proof);
// ARDの資格情報スロット。NUL終端し、64バイトまで乱数で埋める。
Bytes pack_ard_credential(const std::string& value);

}  // namespace iss::proto
