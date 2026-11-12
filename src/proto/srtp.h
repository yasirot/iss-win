// AES-256-CM + HMAC-SHA1-80によるSRTP / SRTCP（srtp.pyの移植）。
//
// 0x1cのやり取りで、方向ごとに46バイトのキーblobを渡す。中身は32バイトの
// マスターキーと14バイトのマスターソルト。セッションキーはRFC 3711 §4.3のKDFで、
// ラベル0/1/2（RTPの暗号 / 認証 / ソルト）と3/4/5（RTCP）から導く。
//
// AppleのHPストリームには、シーケンス番号空間が互いに独立した複数のSSRCが
// 流れるので、ロールオーバーカウンタはSSRCごとに管理する。
#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <optional>

#include "core/bytes.h"
#include "crypto/crypto.h"

namespace iss::proto {

inline constexpr size_t kSrtpKeyBlobLen = 46;
inline constexpr size_t kSrtpAuthTagLen = 10;

// RFC 3711 §4.3.1: (master_salt ^ label@7) || 0000からAES-CMのキーストリームを作る。
Bytes srtp_kdf(const Bytes& master_key, const Bytes& master_salt, uint8_t label, size_t out_len);

// 復号したRTPパケット。`header_len`には固定ヘッダーとCSRC、ヘッダー拡張が
// あればそれも含む。
struct RtpPacket {
  uint32_t ssrc = 0;
  uint16_t seq = 0;
  uint32_t ts = 0;
  uint8_t pt = 0;
  bool marker = false;
  size_t header_len = 0;
  // ヘッダー拡張があるときの、そのprofileと最初のワード。Appleのビデオ
  // （profile 0x9301 / 0x9311、1ワード）では次のとおり。
  // 上位16ビットはストリップピクチャのパケット数。
  // 下位16ビットはピクチャごとの番号。
  uint16_t ext_profile = 0;
  uint32_t ext_word = 0;
  Bytes payload;
};

// 1方向・1プロトコル（RTPかRTCP）分のセッションキー。
struct SrtpKeys {
  std::unique_ptr<crypto::AesCtr> cipher;
  std::unique_ptr<crypto::HmacSha1> auth;
  Bytes salt;  // 14バイト
  SrtpKeys(const Bytes& key_blob, bool rtcp);
};

class SrtpDecryptor {
 public:
  explicit SrtpDecryptor(const Bytes& key_blob);
  // どの候補ROCでも認証タグが合わないとき、またはパケットが壊れているときは
  // nullopt。
  std::optional<RtpPacket> decrypt(const uint8_t* p, size_t n);
  std::optional<RtpPacket> decrypt(const Bytes& b) { return decrypt(b.data(), b.size()); }
  // 認証を通ったパケットのSSRCごとの数（主SSRCグループを選ぶのに使う）。
  const std::map<uint32_t, uint64_t>& counts() const { return counts_; }

 private:
  struct SsrcState {
    uint32_t roc = 0;
    uint16_t max_seq = 0;
  };
  std::optional<RtpPacket> try_decrypt(const uint8_t* p, size_t n, uint16_t seq, uint32_t ssrc, uint32_t roc);

  SrtpKeys keys_;
  std::map<uint32_t, SsrcState> states_;
  std::map<uint32_t, uint64_t> counts_;
};

// ホストがこちらに求めるPT=101キープアライブの送信用。
class SrtpEncryptor {
 public:
  SrtpEncryptor(const Bytes& key_blob, uint32_t ssrc);
  // 自分のストリームの次のパケット。呼ぶたびにseqを+1、タイムスタンプを+480する。
  Bytes encrypt(const Bytes& payload, uint8_t pt = 101, bool marker = false);
  // 番号を明示して1パケット作る（テストでホスト役に使う）。
  Bytes encrypt_rtp(uint16_t seq, uint32_t roc, uint32_t ts, bool marker, uint8_t pt, const Bytes& payload);

 private:
  SrtpKeys keys_;
  uint32_t ssrc_;
  uint32_t seq_ = 0;  // 0..0xFFFF
  uint32_t roc_ = 0;
  uint32_t ts_ = 0;
  std::mutex mu_;
};

class SrtcpDecryptor {
 public:
  explicit SrtcpDecryptor(const Bytes& key_blob);
  std::optional<Bytes> unprotect(const uint8_t* p, size_t n);

 private:
  SrtpKeys keys_;
};

class SrtcpEncryptor {
 public:
  explicit SrtcpEncryptor(const Bytes& key_blob);
  // スレッドセーフ。インデックスと暗号処理は同じロックの中で動く。
  Bytes protect(const Bytes& rtcp);

 private:
  SrtpKeys keys_;
  uint32_t index_ = 0;
  std::mutex mu_;
};

}  // namespace iss::proto
