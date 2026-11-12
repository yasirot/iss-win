// enc1103: AppleのRFB制御チャネル用ストリーム暗号（enc1103.pyの移植）。
//
// 1103エンコーディングのエントリは36バイトを運ぶ。バイト4..36はAES-128 CBCの
// キーとIVで、それぞれ認証から導いたキーでECBラップされている。それ以降の
// 制御メッセージはすべて次の形にまとめて送る。
//
//     u16 BE ciphertext_length | AES-128-CBC( u16 BE len | msg | zero pad | tag )
//
// ここでtag = SHA1(u32 BE counter || tagより前のすべて)。HMACではなく素の
// SHA-1。カウンタは方向ごとにあり、0から始まる。
#pragma once

#include <mutex>
#include <optional>
#include <vector>

#include "core/bytes.h"
#include "crypto/crypto.h"
#include "net/tcp.h"

namespace iss::proto {

class StreamCipher {
 public:
  StreamCipher(const Bytes& key_blob_36, const Bytes& ecb_key);

  // トグル後のmsg 0x10入力ラッパーが暗号化に使うキー。
  const Bytes& cbc_key() const { return cbc_key_; }

  Bytes encrypt_message(const Bytes& plaintext);
  // 暗号のロックを取ったまま暗号化して書き込む。複数スレッドが制御ソケットに
  // 送っても、カウンタの順序と送信順がそろう。
  void encrypt_and_send(net::TcpSocket& sock, const Bytes& plaintext);

  // 暗号文レコード1つ（u16の長さは含まない）。[ctr-1, ctr+5]のどのカウンタでも
  // タグが合わなければnullopt。どちらの場合もCBCの状態は進む。
  std::optional<Bytes> decrypt_message(const uint8_t* p, size_t n);

  // `data`内の完全なレコードをすべて復号し、メッセージと消費したバイト数を返す
  // （途中までの末尾は呼び出し側に残る）。
  std::vector<Bytes> decrypt_stream(const uint8_t* p, size_t n, size_t* consumed);
  std::vector<Bytes> decrypt_stream(const Bytes& b, size_t* consumed = nullptr) {
    return decrypt_stream(b.data(), b.size(), consumed);
  }

 private:
  Bytes encrypt_locked(const Bytes& plaintext);

  Bytes cbc_key_;
  crypto::AesCbc enc_;
  crypto::AesCbc dec_;
  uint32_t enc_ctr_ = 0;
  uint32_t dec_ctr_ = 0;
  std::mutex mu_;
};

}  // namespace iss::proto
