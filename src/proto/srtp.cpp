#include "proto/srtp.h"

#include <algorithm>
#include <stdexcept>

namespace iss::proto {
namespace {

constexpr size_t kMasterKeyLen = 32;
constexpr size_t kMasterSaltLen = 14;
constexpr size_t kRtpHeaderMin = 12;

void check_blob(const Bytes& blob) {
  if (blob.size() != kSrtpKeyBlobLen) throw std::invalid_argument("SRTP key blob must be 46 bytes");
}

// IV = (salt || 0000) ^ (ssrc << 64) ^ (index << 16)。128ビットのビッグエンディアンで扱う。
// SRTPのインデックスは48ビット（ROC || SEQ）、SRTCPのは31ビット。どちらも
// バイト8..13に右詰めで入る。
void build_iv(const Bytes& salt, uint32_t ssrc, uint64_t index, uint8_t iv[16]) {
  std::copy(salt.begin(), salt.end(), iv);
  iv[14] = iv[15] = 0;
  for (int i = 0; i < 4; ++i) iv[4 + i] ^= static_cast<uint8_t>(ssrc >> (24 - 8 * i));
  for (int i = 0; i < 6; ++i) iv[8 + i] ^= static_cast<uint8_t>(index >> (40 - 8 * i));
}

bool tag_matches(const Bytes& mac, const uint8_t* tag) {
  uint8_t diff = 0;  // 定数時間で比較
  for (size_t i = 0; i < kSrtpAuthTagLen; ++i) diff |= static_cast<uint8_t>(mac[i] ^ tag[i]);
  return diff == 0;
}

}  // namespace

Bytes srtp_kdf(const Bytes& master_key, const Bytes& master_salt, uint8_t label, size_t out_len) {
  uint8_t iv[16] = {};
  for (size_t i = 0; i < kMasterSaltLen; ++i) iv[i] = master_salt[i];
  iv[7] ^= label;
  Bytes out(out_len, 0);
  crypto::AesCtr(master_key).apply(iv, out.data(), out.data(), out.size());
  return out;
}

SrtpKeys::SrtpKeys(const Bytes& blob, bool rtcp) {
  check_blob(blob);
  const Bytes key(blob.begin(), blob.begin() + kMasterKeyLen);
  const Bytes msalt(blob.begin() + kMasterKeyLen, blob.end());
  const uint8_t base = rtcp ? 3 : 0;
  Bytes ck = srtp_kdf(key, msalt, base, 32);
  Bytes ak = srtp_kdf(key, msalt, base + 1, 20);
  salt = srtp_kdf(key, msalt, base + 2, 14);
  cipher = std::make_unique<crypto::AesCtr>(ck);
  auth = std::make_unique<crypto::HmacSha1>(ak);
  secure_wipe(ck);
  secure_wipe(ak);
}

// ── SRTP受信 ─────────────────────────────────────────────────────────

SrtpDecryptor::SrtpDecryptor(const Bytes& key_blob) : keys_(key_blob, false) {}

std::optional<RtpPacket> SrtpDecryptor::decrypt(const uint8_t* p, size_t n) {
  if (n < kRtpHeaderMin + kSrtpAuthTagLen) return std::nullopt;
  const uint16_t seq = rd_be16(p + 2);
  const uint32_t ssrc = rd_be32(p + 8);

  const auto it = states_.find(ssrc);
  const bool known = it != states_.end();
  uint32_t guess = 0;
  if (known) {
    const int diff = int(seq) - int(it->second.max_seq);
    if (diff > 0x7FFF) {
      guess = it->second.roc ? it->second.roc - 1 : 0;
    } else if (diff < -0x7FFF) {
      guess = it->second.roc + 1;
    } else {
      guess = it->second.roc;
    }
  }
  // guess、current、guess+1、guess-1の順。重複は除く。
  uint32_t candidates[4] = {guess, known ? it->second.roc : 0, guess + 1, guess ? guess - 1 : 0};
  for (int i = 0; i < 4; ++i) {
    if (std::find(candidates, candidates + i, candidates[i]) != candidates + i) continue;
    const uint32_t roc = candidates[i];
    auto pkt = try_decrypt(p, n, seq, ssrc, roc);
    if (!pkt) continue;
    SsrcState& st = states_[ssrc];
    if (!known) {
      st = {roc, seq};
    } else if ((uint64_t(roc) << 16 | seq) > (uint64_t(st.roc) << 16 | st.max_seq)) {
      st = {roc, seq};
    }
    ++counts_[ssrc];
    return pkt;
  }
  return std::nullopt;
}

std::optional<RtpPacket> SrtpDecryptor::try_decrypt(const uint8_t* p, size_t n, uint16_t seq, uint32_t ssrc,
                                                    uint32_t roc) {
  const size_t body = n - kSrtpAuthTagLen;
  uint8_t roc_be[4];
  wr_be32(roc_be, roc);
  if (!tag_matches(keys_.auth->mac(p, body, roc_be, 4), p + body)) return std::nullopt;

  size_t hdr = kRtpHeaderMin + (p[0] & 0x0F) * 4;
  RtpPacket out;
  if ((p[0] >> 4) & 1) {  // ヘッダー拡張
    if (hdr + 4 > body) return std::nullopt;
    const size_t words = rd_be16(p + hdr + 2);
    if (words && hdr + 8 <= body) {
      out.ext_profile = rd_be16(p + hdr);
      out.ext_word = rd_be32(p + hdr + 4);
    }
    hdr += 4 + words * 4;
  }
  if (hdr > body) return std::nullopt;

  out.ssrc = ssrc;
  out.seq = seq;
  out.ts = rd_be32(p + 4);
  out.pt = p[1] & 0x7F;
  out.marker = (p[1] & 0x80) != 0;
  out.header_len = hdr;
  out.payload.resize(body - hdr);
  if (!out.payload.empty()) {
    uint8_t iv[16];
    build_iv(keys_.salt, ssrc, uint64_t(roc) << 16 | seq, iv);
    keys_.cipher->apply(iv, p + hdr, out.payload.data(), out.payload.size());
  }
  return out;
}

// ── SRTP送信 ────────────────────────────────────────────────────────────

SrtpEncryptor::SrtpEncryptor(const Bytes& key_blob, uint32_t ssrc) : keys_(key_blob, false), ssrc_(ssrc) {}

Bytes SrtpEncryptor::encrypt(const Bytes& payload, uint8_t pt, bool marker) {
  uint16_t seq;
  uint32_t roc, ts;
  {
    std::lock_guard lk(mu_);
    seq = static_cast<uint16_t>(seq_);
    roc = roc_;
    ts = ts_;
    if (++seq_ > 0xFFFF) {
      seq_ = 0;
      ++roc_;
    }
    ts_ += 480;
  }
  return encrypt_rtp(seq, roc, ts, marker, pt, payload);
}

Bytes SrtpEncryptor::encrypt_rtp(uint16_t seq, uint32_t roc, uint32_t ts, bool marker, uint8_t pt,
                                 const Bytes& payload) {
  std::lock_guard lk(mu_);  // 暗号器の作業バッファを共有しているため
  ByteWriter w(kRtpHeaderMin + payload.size() + kSrtpAuthTagLen);
  w.u8(0x80).u8(static_cast<uint8_t>((pt & 0x7F) | (marker ? 0x80 : 0))).be16(seq).be32(ts).be32(ssrc_);
  w.bytes(payload);
  Bytes out = w.take();
  if (!payload.empty()) {
    uint8_t iv[16];
    build_iv(keys_.salt, ssrc_, uint64_t(roc) << 16 | seq, iv);
    keys_.cipher->apply(iv, out.data() + kRtpHeaderMin, out.data() + kRtpHeaderMin, payload.size());
  }
  uint8_t roc_be[4];
  wr_be32(roc_be, roc);
  const Bytes mac = keys_.auth->mac(out.data(), out.size(), roc_be, 4);
  out.insert(out.end(), mac.begin(), mac.begin() + kSrtpAuthTagLen);
  return out;
}

// ── SRTCP ────────────────────────────────────────────────────────────────

SrtcpDecryptor::SrtcpDecryptor(const Bytes& key_blob) : keys_(key_blob, true) {}

std::optional<Bytes> SrtcpDecryptor::unprotect(const uint8_t* p, size_t n) {
  if (n < 8 + 4 + kSrtpAuthTagLen) return std::nullopt;
  const size_t body = n - kSrtpAuthTagLen;
  if (!tag_matches(keys_.auth->mac(p, body), p + body)) return std::nullopt;
  const uint32_t e_index = rd_be32(p + body - 4);
  Bytes out(p, p + body - 4);  // ヘッダー + （暗号化された）本文。E||indexは含まない
  if (e_index & 0x80000000u) {
    uint8_t iv[16];
    build_iv(keys_.salt, rd_be32(p + 4), e_index & 0x7FFFFFFFu, iv);
    keys_.cipher->apply(iv, out.data() + 8, out.data() + 8, out.size() - 8);
  }
  return out;
}

SrtcpEncryptor::SrtcpEncryptor(const Bytes& key_blob) : keys_(key_blob, true) {}

Bytes SrtcpEncryptor::protect(const Bytes& rtcp) {
  if (rtcp.size() < 8) throw std::invalid_argument("RTCP packet shorter than its header");
  std::lock_guard lk(mu_);
  const uint32_t index = index_++ & 0x7FFFFFFFu;
  Bytes out = rtcp;
  uint8_t iv[16];
  build_iv(keys_.salt, rd_be32(rtcp.data() + 4), index, iv);
  keys_.cipher->apply(iv, out.data() + 8, out.data() + 8, out.size() - 8);
  uint8_t e_index[4];
  wr_be32(e_index, 0x80000000u | index);
  out.insert(out.end(), e_index, e_index + 4);
  const Bytes mac = keys_.auth->mac(out.data(), out.size());
  out.insert(out.end(), mac.begin(), mac.begin() + kSrtpAuthTagLen);
  return out;
}

}  // namespace iss::proto
