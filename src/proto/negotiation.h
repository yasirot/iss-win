// connect()から0x1cの応答までを進めるTCP側のハンドシェイク処理（negotiation.pyと、
// rfb.pyのwarmup_tcp / do_protocol_handshakeの移植）。
//
//   1. 必要ならウォームアップのTCP（バージョン交換、切断、約1.4秒待つ）
//   2. TCP + RFBバージョン + セキュリティタイプ
//   3. 認証。SRPで試し、失敗したらnon-SRP（逆順もある）。新しいTCPで行う
//   4. ClientInit + ServerInit
//   5. ホストのコンソールユーザーが接続ユーザーと違うときはSessionSelect。
//      cmd=0でコンソールを共有する（Macにポップアップが出る）か、cmd=2で別セッション
//      にする（2本目のTCPで認証し直し、暗号化した資格情報を送る）
//   6. 平文でViewerInfo + 続きの0x12、VirtualDisplay、SetEncodingsを送る
//   7. まとめて届く1010/1011/1103の応答 → enc1103のcipher、PostEncryptionToggle
//   8. 暗号化してSetEncodings、0x1c、FramebufferUpdateRequestを送る
//   9. 0x1cの応答 → キャンバスの寸法。エンコーダーの準備ができるまで問い合わせ直す
//
// 呼ぶ前にUDPの受信側をbindしておくこと。0x1cの応答から1秒もたたずにメディアが
// まとめて届き始める。ここの処理はすべてブロックする（SessionSelectのポップアップが
// クリックを待つ間は最大1分）ので、UIスレッド以外で呼ぶ。
#pragma once

#include <functional>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include "core/bytes.h"
#include "net/tcp.h"
#include "proto/enc1103.h"
#include "proto/offers.h"
#include "proto/rfb.h"

namespace iss::proto {

class HandshakeError : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

enum class AuthMode { Srp, NonSrp };
enum class SessionChoice { ShareConsole, AltSession };

// 通信の各段階の間の待ち時間。既定値はPythonクライアントのもので、それは
// Screen Sharing.appの動きをまねている。短くすると遅い回線でつながらなくなる。
struct HandshakeTiming {
  int connect_timeout_ms = 15000;
  int io_timeout_ms = 15000;
  int warmup_dwell_ms = 1400;       // ウォームアップのTCPを閉じた後
  int post_viewer_info_ms = 100;
  int enc1103_wait_ms = 10000;      // まとめて届く応答の最初の1バイトまで
  int burst_quiet_ms = 1000;        // この間なにも来なければ応答の終わりとみなす
  int post_toggle_ms = 200;
  int drain_quiet_ms = 500;
  int answer_timeout_ms = 5000;
  int requery_interval_ms = 200;    // キャンバスの寸法が不正 → 0x1cを送り直す
  int requery_limit = 16;
  int ss_peek_ms = 2000;            // SessionSelectのプロンプトが来ているか
  int ss_prompt_ms = 500;
  int ss_ack_ms = 60000;            // cmd=0はMac側のクリックを待つ
};

struct ConnectOptions {
  std::string host;
  uint16_t port = 5900;
  std::string username;
  std::string password;
  AuthMode auth_mode = AuthMode::Srp;  // 失敗したらもう一方のモードを試す
  bool warmup = true;
  // ホストに伝える仮想ディスプレイ（hdrもここで指定する）。curtainがオフのときは
  // 送らず、ホストはカーテンをかけずに物理画面を流す。
  rfb::VirtualDisplayParams display;
  // 2台目の仮想ディスプレイ（高性能モードでcurtainあり）。このときofferにも
  // 2本目の映像ストリームを入れる必要がある。
  std::optional<rfb::VirtualDisplayParams> display2;
  bool curtain = true;
  // Macに別の人がログインしているときのSessionSelectのモード。どちらも未設定で
  // コールバックがあれば、それで尋ねる（引数はコンソールユーザー名）。
  // どちらも未設定でコールバックもなければコンソールを共有する。
  bool share_console = false;
  bool alt_session = false;
  std::function<SessionChoice(const std::string& console_user)> on_session_choice;
  // PythonクライアントのISS_LEGACY_CURSOR=1に当たる。ホストはカーソルを映像に
  // 描き込み、enc-1104の送信を始めさせるFramebufferUpdateRequestも送らない。
  bool legacy_cursor = false;
  // 送るoffer。nulloptならOfferOptions::from_env()から作る。
  std::optional<Offers> offers;
  // falseならScreen Sharingの標準モード。0x1cは使わず、ホストは画面を
  // `encodings`の形式でframebuffer updateの矩形として（TCPで）送る。
  bool media = true;
  std::vector<int32_t> encodings;  // 暗号化後のSetEncodings。空ならHPのリスト
  HandshakeTiming timing;
};

struct NegotiationResult {
  net::TcpSocket sock;  // 暗号化RFBモード。cipherを通して送る
  std::unique_ptr<StreamCipher> cipher;
  NegotiationKeys keys;
  Offers offers;        // 送ったもの（セッションがそのSSRCを使う）
  // 認証後に得る16バイトのenc1103マスター鍵（dissectorの--initial-key-hexに当たる）。
  Bytes ecb_key;
  int server_width = 0;
  int server_height = 0;
  Bytes server_pixel_format;  // ServerInitの16バイトのPIXEL_FORMAT
  CanvasDims canvas;    // エンコーダーが最後まで準備できなかった（またはmediaがオフの）ときは無効
  bool alt_session = false;  // SessionSelectで選んだ後の実際のモード
  // 応答を待つ間に復号した、応答以外のメッセージ（たいていは最初のenc-1104の
  // カーソル矩形）。cipherの状態はもうこれらの先へ進んでいるので、RXループは
  // 最初にこれらを処理すること。
  std::vector<Bytes> leftover_msgs;
  // 受信済みだがまだそろっていないレコードのバイト列。RXループが先頭に付け足す。
  Bytes rx_pending;
};

NegotiationResult connect_and_negotiate(const ConnectOptions& opt);

// バージョン交換とセキュリティタイプの受信。セキュリティタイプの一覧を返す。
// サーバーが1つも出さない（レート制限）ときは、その理由の文字列でHandshakeErrorを
// 投げる。バナーがRFBでないときも同じ。`server_version`を渡すと、サーバーの
// バナーを改行なしで入れる（"RFB 003.889"）。
Bytes do_protocol_handshake(net::TcpSocket& sock, std::string* server_version = nullptr);

// Appleがセッションの前に張る下見の接続（2本のTCPの1本目）。バージョンのバナーを
// 交換して切る。これがあると、ロック → ログイン → デスクトップと画面が移っても
// デーモンが本番のTCPを切らず、セッションが続く。
void warmup_tcp(const std::string& host, uint16_t port, const HandshakeTiming& timing = {});

// SessionSelectの本体（テスト用に公開）。
Bytes build_ss_cmd0_body(const std::string& console_user);
Bytes build_ss_cmd2_body(const std::string& username, const std::string& password, const Bytes& ecb_key);

}  // namespace iss::proto
