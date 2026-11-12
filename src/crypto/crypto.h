// Windows CNG（bcrypt.dll / crypt32.dll）の薄いラッパー。ハッシュ、PBKDF2、
// AES-ECB / AES-CBC、RSA PKCS#1 v1.5の暗号化、システムの乱数生成器を扱う。
// Python実装の `cryptography` + `pycryptodome` の代わりになる。
#pragma once

#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>

#include "core/bytes.h"

namespace iss::crypto {

class CryptoError : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

Bytes random_bytes(size_t n);

Bytes sha1(const uint8_t* p, size_t n);
Bytes sha256(const uint8_t* p, size_t n);
Bytes sha512(const uint8_t* p, size_t n);
inline Bytes sha1(const Bytes& b) { return sha1(b.data(), b.size()); }
inline Bytes sha256(const Bytes& b) { return sha256(b.data(), b.size()); }
inline Bytes sha512(const Bytes& b) { return sha512(b.data(), b.size()); }

Bytes pbkdf2_hmac_sha512(std::string_view password, const Bytes& salt, uint64_t iterations,
                         size_t dk_len);

// AES-ECB、パディングなし。データ長は16の倍数でなければならない。
Bytes aes_ecb_encrypt(const Bytes& key, const uint8_t* p, size_t n);
Bytes aes_ecb_decrypt(const Bytes& key, const uint8_t* p, size_t n);
inline Bytes aes_ecb_encrypt(const Bytes& key, const Bytes& b) { return aes_ecb_encrypt(key, b.data(), b.size()); }
inline Bytes aes_ecb_decrypt(const Bytes& key, const Bytes& b) { return aes_ecb_decrypt(key, b.data(), b.size()); }

// AES-CBC、パディングなし。チェイニングの状態を呼び出しをまたいで引き継ぐ
// （pycryptodomeのCBCオブジェクトに1レコードずつ渡すのと同じ）。
class AesCbc {
 public:
  AesCbc(const Bytes& key, const Bytes& iv);
  ~AesCbc();
  AesCbc(const AesCbc&) = delete;
  AesCbc& operator=(const AesCbc&) = delete;

  Bytes encrypt(const uint8_t* p, size_t n);
  Bytes decrypt(const uint8_t* p, size_t n);
  Bytes encrypt(const Bytes& b) { return encrypt(b.data(), b.size()); }
  Bytes decrypt(const Bytes& b) { return decrypt(b.data(), b.size()); }

 private:
  void* key_ = nullptr;  // BCRYPT_KEY_HANDLE
  Bytes iv_;
};

// 鍵を使い回せるAES-CTR（SRTPのAES-CM）。カウンターブロックは `iv` から始め、
// 128ビットのビッグエンディアン整数として1ずつ増やす。
class AesCtr {
 public:
  explicit AesCtr(const Bytes& key);
  ~AesCtr();
  AesCtr(const AesCtr&) = delete;
  AesCtr& operator=(const AesCtr&) = delete;

  // out[i] = in[i] ^ keystream[i]。`out` と `in` は同じ領域でもよい。
  void apply(const uint8_t iv[16], const uint8_t* in, uint8_t* out, size_t n);

 private:
  void* key_ = nullptr;  // BCRYPT_KEY_HANDLE (AES-ECB)
  Bytes blocks_;         // カウンターとキーストリームの作業領域
};

// 鍵を使い回せるHMAC-SHA1（SRTP / SRTCPの認証タグ用）。
class HmacSha1 {
 public:
  explicit HmacSha1(const Bytes& key);
  ~HmacSha1();
  HmacSha1(const HmacSha1&) = delete;
  HmacSha1& operator=(const HmacSha1&) = delete;

  // a || bのHMAC（bは空でもよい）。20バイトのダイジェストを切り詰めずに返す。
  Bytes mac(const uint8_t* a, size_t na, const uint8_t* b = nullptr, size_t nb = 0);

 private:
  void* hash_ = nullptr;  // BCRYPT_HASH_HANDLE（使い回せる）
};

class RsaPublicKey {
 public:
  // DERのSubjectPublicKeyInfoか、包まれていないPKCS#1のRSAPublicKeyを受け付ける。
  static RsaPublicKey from_der(const uint8_t* p, size_t n);
  static RsaPublicKey from_der(const Bytes& b) { return from_der(b.data(), b.size()); }

  RsaPublicKey(RsaPublicKey&& o) noexcept : key_(o.key_) { o.key_ = nullptr; }
  RsaPublicKey& operator=(RsaPublicKey&& o) noexcept;
  ~RsaPublicKey();

  size_t bits() const;
  Bytes encrypt_pkcs1v15(const Bytes& plaintext) const;

 private:
  explicit RsaPublicKey(void* key) : key_(key) {}
  void* key_ = nullptr;  // BCRYPT_KEY_HANDLE
};

}  // namespace iss::crypto
