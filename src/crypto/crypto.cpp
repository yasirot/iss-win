#include "crypto/crypto.h"

#include <windows.h>
#include <bcrypt.h>
#include <wincrypt.h>

#include <algorithm>
#include <format>

namespace iss::crypto {
namespace {

void check(NTSTATUS st, const char* what) {
  if (!BCRYPT_SUCCESS(st)) {
    throw CryptoError(std::format("{} failed (NTSTATUS 0x{:08x})", what, static_cast<uint32_t>(st)));
  }
}

Bytes hash_with(BCRYPT_ALG_HANDLE alg, size_t out_len, const uint8_t* p, size_t n) {
  Bytes out(out_len);
  check(BCryptHash(alg, nullptr, 0, const_cast<PUCHAR>(p), static_cast<ULONG>(n), out.data(),
                   static_cast<ULONG>(out.size())),
        "BCryptHash");
  return out;
}

BCRYPT_KEY_HANDLE aes_key(BCRYPT_ALG_HANDLE alg, const Bytes& key) {
  if (key.size() != 16 && key.size() != 24 && key.size() != 32) {
    throw CryptoError("AES key must be 16/24/32 bytes");
  }
  BCRYPT_KEY_HANDLE h = nullptr;
  check(BCryptGenerateSymmetricKey(alg, &h, nullptr, 0, const_cast<PUCHAR>(key.data()),
                                   static_cast<ULONG>(key.size()), 0),
        "BCryptGenerateSymmetricKey");
  return h;
}

void require_blocks(size_t n) {
  if (n % 16) throw CryptoError("AES input must be a multiple of 16 bytes");
}

Bytes ecb(const Bytes& key, const uint8_t* p, size_t n, bool enc) {
  require_blocks(n);
  BCRYPT_KEY_HANDLE h = aes_key(BCRYPT_AES_ECB_ALG_HANDLE, key);
  Bytes out(n);
  ULONG got = 0;
  NTSTATUS st = enc ? BCryptEncrypt(h, const_cast<PUCHAR>(p), static_cast<ULONG>(n), nullptr, nullptr,
                                    0, out.data(), static_cast<ULONG>(n), &got, 0)
                    : BCryptDecrypt(h, const_cast<PUCHAR>(p), static_cast<ULONG>(n), nullptr, nullptr,
                                    0, out.data(), static_cast<ULONG>(n), &got, 0);
  BCryptDestroyKey(h);
  check(st, enc ? "AES-ECB encrypt" : "AES-ECB decrypt");
  return out;
}

}  // namespace

Bytes random_bytes(size_t n) {
  Bytes out(n);
  if (n) {
    check(BCryptGenRandom(nullptr, out.data(), static_cast<ULONG>(n), BCRYPT_USE_SYSTEM_PREFERRED_RNG),
          "BCryptGenRandom");
  }
  return out;
}

Bytes sha1(const uint8_t* p, size_t n) { return hash_with(BCRYPT_SHA1_ALG_HANDLE, 20, p, n); }
Bytes sha256(const uint8_t* p, size_t n) { return hash_with(BCRYPT_SHA256_ALG_HANDLE, 32, p, n); }
Bytes sha512(const uint8_t* p, size_t n) { return hash_with(BCRYPT_SHA512_ALG_HANDLE, 64, p, n); }

Bytes pbkdf2_hmac_sha512(std::string_view password, const Bytes& salt, uint64_t iterations,
                         size_t dk_len) {
  Bytes out(dk_len);
  // CNGは長さが0でも、パスワードのポインターがnullだと受け付けない。
  static const UCHAR kEmpty = 0;
  auto* pw = password.empty() ? const_cast<PUCHAR>(&kEmpty)
                              : reinterpret_cast<PUCHAR>(const_cast<char*>(password.data()));
  check(BCryptDeriveKeyPBKDF2(BCRYPT_HMAC_SHA512_ALG_HANDLE, pw, static_cast<ULONG>(password.size()),
                              const_cast<PUCHAR>(salt.data()), static_cast<ULONG>(salt.size()),
                              iterations, out.data(), static_cast<ULONG>(out.size()), 0),
        "BCryptDeriveKeyPBKDF2");
  return out;
}

Bytes aes_ecb_encrypt(const Bytes& key, const uint8_t* p, size_t n) { return ecb(key, p, n, true); }
Bytes aes_ecb_decrypt(const Bytes& key, const uint8_t* p, size_t n) { return ecb(key, p, n, false); }

// ── AES-CBC ──────────────────────────────────────────────────────────────

AesCbc::AesCbc(const Bytes& key, const Bytes& iv) : iv_(iv) {
  if (iv.size() != 16) throw CryptoError("AES-CBC IV must be 16 bytes");
  key_ = aes_key(BCRYPT_AES_CBC_ALG_HANDLE, key);
}

AesCbc::~AesCbc() {
  if (key_) BCryptDestroyKey(static_cast<BCRYPT_KEY_HANDLE>(key_));
  secure_wipe(iv_);
}

Bytes AesCbc::encrypt(const uint8_t* p, size_t n) {
  require_blocks(n);
  Bytes out(n);
  if (!n) return out;
  Bytes iv = iv_;  // CNGはIVのバッファを書き換えるので、チェインは自前で管理する。
  ULONG got = 0;
  check(BCryptEncrypt(static_cast<BCRYPT_KEY_HANDLE>(key_), const_cast<PUCHAR>(p), static_cast<ULONG>(n),
                      nullptr, iv.data(), 16, out.data(), static_cast<ULONG>(n), &got, 0),
        "AES-CBC encrypt");
  iv_.assign(out.end() - 16, out.end());
  return out;
}

Bytes AesCbc::decrypt(const uint8_t* p, size_t n) {
  require_blocks(n);
  Bytes out(n);
  if (!n) return out;
  Bytes iv = iv_;
  Bytes next_iv(p + n - 16, p + n);
  ULONG got = 0;
  check(BCryptDecrypt(static_cast<BCRYPT_KEY_HANDLE>(key_), const_cast<PUCHAR>(p), static_cast<ULONG>(n),
                      nullptr, iv.data(), 16, out.data(), static_cast<ULONG>(n), &got, 0),
        "AES-CBC decrypt");
  iv_ = std::move(next_iv);
  return out;
}

// ── AES-CTR ──────────────────────────────────────────────────────────────

AesCtr::AesCtr(const Bytes& key) { key_ = aes_key(BCRYPT_AES_ECB_ALG_HANDLE, key); }

AesCtr::~AesCtr() {
  if (key_) BCryptDestroyKey(static_cast<BCRYPT_KEY_HANDLE>(key_));
  secure_wipe(blocks_);
}

void AesCtr::apply(const uint8_t iv[16], const uint8_t* in, uint8_t* out, size_t n) {
  if (!n) return;
  const size_t len = (n + 15) & ~size_t(15);
  blocks_.resize(len);
  uint8_t ctr[16];
  std::copy(iv, iv + 16, ctr);
  for (size_t off = 0; off < len; off += 16) {
    std::copy(ctr, ctr + 16, blocks_.begin() + off);
    for (int i = 15; i >= 0 && ++ctr[i] == 0; --i) {
    }
  }
  ULONG got = 0;
  check(BCryptEncrypt(static_cast<BCRYPT_KEY_HANDLE>(key_), blocks_.data(), static_cast<ULONG>(len), nullptr,
                      nullptr, 0, blocks_.data(), static_cast<ULONG>(len), &got, 0),
        "AES-CTR keystream");
  for (size_t i = 0; i < n; ++i) out[i] = in[i] ^ blocks_[i];
}

// ── HMAC-SHA1 ────────────────────────────────────────────────────────────

HmacSha1::HmacSha1(const Bytes& key) {
  BCRYPT_HASH_HANDLE h = nullptr;
  check(BCryptCreateHash(BCRYPT_HMAC_SHA1_ALG_HANDLE, &h, nullptr, 0, const_cast<PUCHAR>(key.data()),
                         static_cast<ULONG>(key.size()), BCRYPT_HASH_REUSABLE_FLAG),
        "BCryptCreateHash(HMAC-SHA1)");
  hash_ = h;
}

HmacSha1::~HmacSha1() {
  if (hash_) BCryptDestroyHash(static_cast<BCRYPT_HASH_HANDLE>(hash_));
}

Bytes HmacSha1::mac(const uint8_t* a, size_t na, const uint8_t* b, size_t nb) {
  auto h = static_cast<BCRYPT_HASH_HANDLE>(hash_);
  if (na) check(BCryptHashData(h, const_cast<PUCHAR>(a), static_cast<ULONG>(na), 0), "HMAC update");
  if (nb) check(BCryptHashData(h, const_cast<PUCHAR>(b), static_cast<ULONG>(nb), 0), "HMAC update");
  Bytes out(20);
  check(BCryptFinishHash(h, out.data(), static_cast<ULONG>(out.size()), 0), "HMAC finish");
  return out;
}

// ── RSA ──────────────────────────────────────────────────────────────────

RsaPublicKey RsaPublicKey::from_der(const uint8_t* p, size_t n) {
  BCRYPT_KEY_HANDLE key = nullptr;

  // SubjectPublicKeyInfo ("BEGIN PUBLIC KEY").
  CERT_PUBLIC_KEY_INFO* spki = nullptr;
  DWORD spki_len = 0;
  if (CryptDecodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, p, static_cast<DWORD>(n),
                          CRYPT_DECODE_ALLOC_FLAG, nullptr, &spki, &spki_len)) {
    BOOL ok = CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING, spki, 0, nullptr, &key);
    LocalFree(spki);
    if (!ok) throw CryptoError(std::format("CryptImportPublicKeyInfoEx2 failed ({})", GetLastError()));
    return RsaPublicKey(key);
  }

  // 包まれていないPKCS#1のRSAPublicKey（"BEGIN RSA PUBLIC KEY"）→ BCRYPT_RSAKEY_BLOB。
  BYTE* blob = nullptr;
  DWORD blob_len = 0;
  if (!CryptDecodeObjectEx(X509_ASN_ENCODING, CNG_RSA_PUBLIC_KEY_BLOB, p, static_cast<DWORD>(n),
                           CRYPT_DECODE_ALLOC_FLAG, nullptr, &blob, &blob_len)) {
    throw CryptoError(std::format("RSA public key DER not recognised ({})", GetLastError()));
  }
  NTSTATUS st = BCryptImportKeyPair(BCRYPT_RSA_ALG_HANDLE, nullptr, BCRYPT_RSAPUBLIC_BLOB, &key, blob,
                                    blob_len, 0);
  LocalFree(blob);
  check(st, "BCryptImportKeyPair");
  return RsaPublicKey(key);
}

RsaPublicKey& RsaPublicKey::operator=(RsaPublicKey&& o) noexcept {
  if (this != &o) {
    if (key_) BCryptDestroyKey(static_cast<BCRYPT_KEY_HANDLE>(key_));
    key_ = o.key_;
    o.key_ = nullptr;
  }
  return *this;
}

RsaPublicKey::~RsaPublicKey() {
  if (key_) BCryptDestroyKey(static_cast<BCRYPT_KEY_HANDLE>(key_));
}

size_t RsaPublicKey::bits() const {
  DWORD bits = 0;
  ULONG got = 0;
  check(BCryptGetProperty(static_cast<BCRYPT_KEY_HANDLE>(key_), BCRYPT_KEY_LENGTH,
                          reinterpret_cast<PUCHAR>(&bits), sizeof(bits), &got, 0),
        "BCryptGetProperty(KEY_LENGTH)");
  return bits;
}

Bytes RsaPublicKey::encrypt_pkcs1v15(const Bytes& plaintext) const {
  auto h = static_cast<BCRYPT_KEY_HANDLE>(key_);
  ULONG need = 0;
  check(BCryptEncrypt(h, const_cast<PUCHAR>(plaintext.data()), static_cast<ULONG>(plaintext.size()),
                      nullptr, nullptr, 0, nullptr, 0, &need, BCRYPT_PAD_PKCS1),
        "RSA encrypt (size)");
  Bytes out(need);
  check(BCryptEncrypt(h, const_cast<PUCHAR>(plaintext.data()), static_cast<ULONG>(plaintext.size()),
                      nullptr, nullptr, 0, out.data(), need, &need, BCRYPT_PAD_PKCS1),
        "RSA encrypt");
  out.resize(need);
  return out;
}

}  // namespace iss::crypto
