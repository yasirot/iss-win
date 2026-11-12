#include "proto/enc1103.h"

#include <algorithm>
#include <format>

namespace iss::proto {
namespace {

constexpr size_t kMacLen = 20;
constexpr size_t kBlock = 16;
constexpr uint32_t kDecryptCounterWindow = 6;  // 6メッセージまでの抜けを許す

Bytes unwrap(const Bytes& ecb_key, const Bytes& blob, size_t off) {
  return crypto::aes_ecb_decrypt(ecb_key, blob.data() + off, 16);
}

Bytes tag_for(uint32_t counter, const uint8_t* body, size_t n) {
  Bytes buf(4 + n);
  wr_be32(buf.data(), counter);
  std::copy_n(body, n, buf.begin() + 4);
  return crypto::sha1(buf);
}

void check_blob(const Bytes& blob) {
  if (blob.size() != 36) {
    throw std::invalid_argument(std::format("enc1103 key blob must be 36 bytes, got {}", blob.size()));
  }
}

}  // namespace

StreamCipher::StreamCipher(const Bytes& key_blob_36, const Bytes& ecb_key)
    : cbc_key_((check_blob(key_blob_36), unwrap(ecb_key, key_blob_36, 4))),
      // キーとIVは両方向で同じ。CBCの状態は方向ごとに別。
      enc_(cbc_key_, unwrap(ecb_key, key_blob_36, 20)),
      dec_(cbc_key_, unwrap(ecb_key, key_blob_36, 20)) {}

Bytes StreamCipher::encrypt_locked(const Bytes& plaintext) {
  const uint32_t counter = enc_ctr_;
  size_t pad = (kBlock - (2 + plaintext.size() + kMacLen) % kBlock) % kBlock;
  ByteWriter framed(2 + plaintext.size() + pad + kMacLen);
  framed.be16(static_cast<uint16_t>(plaintext.size())).bytes(plaintext).zeros(pad);
  Bytes block = framed.take();
  Bytes mac = tag_for(counter, block.data(), block.size());
  block.insert(block.end(), mac.begin(), mac.end());
  Bytes ct = enc_.encrypt(block);
  enc_ctr_ = counter + 1;
  return ByteWriter(2 + ct.size()).be16(static_cast<uint16_t>(ct.size())).bytes(ct).take();
}

Bytes StreamCipher::encrypt_message(const Bytes& plaintext) {
  std::lock_guard lk(mu_);
  return encrypt_locked(plaintext);
}

void StreamCipher::encrypt_and_send(net::TcpSocket& sock, const Bytes& plaintext) {
  std::lock_guard lk(mu_);
  sock.send_all(encrypt_locked(plaintext));
}

std::optional<Bytes> StreamCipher::decrypt_message(const uint8_t* p, size_t n) {
  if (!n || n % kBlock) return std::nullopt;
  Bytes plaintext;
  uint32_t ctr_start;
  {
    std::lock_guard lk(mu_);
    plaintext = dec_.decrypt(p, n);
    ctr_start = dec_ctr_++;
  }
  if (n <= kMacLen) return plaintext;
  const size_t body_len = plaintext.size() - kMacLen;
  const uint8_t* mac = plaintext.data() + body_len;
  uint32_t first = ctr_start ? ctr_start - 1 : 0;
  for (uint32_t c = first; c < ctr_start + kDecryptCounterWindow; ++c) {
    Bytes want = tag_for(c, plaintext.data(), body_len);
    if (std::equal(want.begin(), want.end(), mac)) {
      {
        std::lock_guard lk(mu_);
        dec_ctr_ = c + 1;  // 一致したカウンタに合わせ直す
      }
      size_t inner = rd_be16(plaintext.data());
      inner = std::min(inner, body_len - 2);
      return Bytes(plaintext.begin() + 2, plaintext.begin() + 2 + inner);
    }
  }
  return std::nullopt;
}

std::vector<Bytes> StreamCipher::decrypt_stream(const uint8_t* p, size_t n, size_t* consumed) {
  std::vector<Bytes> out;
  size_t pos = 0;
  while (pos + 2 <= n) {
    size_t len = rd_be16(p + pos);
    if (len == 0 || len % kBlock || pos + 2 + len > n) break;
    auto msg = decrypt_message(p + pos + 2, len);
    pos += 2 + len;
    if (msg) out.push_back(std::move(*msg));
  }
  if (consumed) *consumed = pos;
  return out;
}

}  // namespace iss::proto
