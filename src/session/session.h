// 動作中の画面共有セッション。session.pyの受信側にあたる。
//
//   connect()  最初にUDP 5900 / 5901（2台目のディスプレイがあれば5902も）を
//              bindする（メディアの最初のまとまりは0x1cの応答から約100 ms以内に
//              届くため）。ハンドシェイクの間はそのポートから送ってローカルの
//              ファイアウォールに穴を開け、connect_and_negotiateもメディアの
//              届く先と同じ1つのアドレスに対して行う（名前にIPv4があればIPv4、
//              なければIPv6）。そのあと開始時のまとまりを待つ。待つのは主SSRC
//              （パケットが最も多いもの）とパラメータセット（H.264はAppleの0x92
//              パケットから、HEVCはストリームから）。まとまりが足りないときは、
//              Pythonクライアントと同じくハンドシェイクからやり直す。
//   スレッド   ビデオストリームごとにvideo-rx（recv → キュー）とvideo（SRTP →
//              RTPのグループ → NALU → デコーダ → 最新フレーム）。ほかにctrl-rx
//              （SRTCPの送信者レポート）、tcp-rx（暗号化された制御チャネル）、
//              tx（キープアライブ、RR/SR、NACK、キーフレーム要求）。
//
// 仮想ディスプレイが2台（高パフォーマンス）のとき、Macは2台目を1台目の右に置き、
// それぞれを別のビデオストリームで送る。2台目はUDPのport + 2で、SRTPの鍵とSSRC
// グループも別に持ち、0x1cの2つ目のビデオブロックとして提示する。デコーダは
// ストリームごとに持つ。ポインタ座標は両方のディスプレイにまたがる
// （AppleDisplayLayoutの矩形）。
//
// ビデオはH.264か、4本の帯に分かれたHEVC。4:4:4はIntel Quick Syncで、4:2:0は
// D3D11VAでデコードする。ピクチャを失っておかしくなるのはその帯だけで、その帯は
// すぐに要求したリフレッシュを待つ。音声は提示する（0x1cに必要なため）が、
// プレーヤーができるまでは捨てる。
#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "core/bytes.h"
#include "core/perf_stat.h"
#include "media/hevc_refs.h"
#include "media/video_decoder.h"
#include "net/udp.h"
#include "proto/negotiation.h"
#include "proto/srtp.h"
#include "session/control_messages.h"
#include "session/framebuffer.h"
#include "session/picture_assembler.h"
#include "session/rtp_grouper.h"

namespace iss::session {

struct SessionOptions {
  std::string host;
  uint16_t port = 5900;  // TCP。メディアのポートはこれの+1と（2台目のディスプレイは）+2
  net::Family family = net::Family::Any;  // 高パフォーマンスで使うアドレスファミリ（TCPもUDPも）
  std::string username;
  std::string password;
  proto::AuthMode auth_mode = proto::AuthMode::Srp;
  rfb::VirtualDisplayParams display;
  // 2台目の仮想ディスプレイ（カーテン付きの高パフォーマンス）。2本目の
  // ビデオストリームになる。
  std::optional<rfb::VirtualDisplayParams> display2;
  bool curtain = true;
  // カーソルをenc-1104の形として送らせず、ホストにビデオへ描き込ませる
  // （PythonクライアントのISS_LEGACY_CURSOR=1）。
  bool legacy_cursor = false;
  bool share_console = false;
  bool alt_session = false;
  // Macに別の人がログインしていて、どちらのフラグも立っていないときに尋ねる。
  std::function<proto::SessionChoice(const std::string& console_user)> on_session_choice;
  int adapter_index = -1;  // D3D11VAで使うDXGIアダプタ
  bool prefer_hwaccel = true;
  // ハンドシェイクの調整値。既定値はScreen Sharing.appに合わせてある（テストでは短くする）。
  bool warmup = true;
  proto::HandshakeTiming timing;
  // 統計の行を出すたびにフレームのタイミングの行も出す（--perf）。
  bool perf = false;
  // falseなら標準モード。UDPのメディアは使わず、画面は制御チャネル上の
  // フレームバッファ更新として`encodings`で届く（空ならHPのリスト）。
  bool media = true;
  std::vector<int32_t> encodings;
  // 復号した制御チャネルのレコードをすべてこのファイルに追記する（u32 LEの
  // 長さ + 本体）。プロトコル解析用。
  std::wstring dump_path;
  // 送ったボタンの変化をすべてログに出す（--log-input）。
  bool log_input = false;
  // 実験用（--hevc-probe）。HEVCを提示してストリームのSPSからサイズを読み、
  // そのサイズを添えて接続を失敗させる。デコードは何もしない。
  bool hevc_probe = false;
  // --hevc: HEVC（4:4:4、4タイル）を提示し、Intel Quick Syncでデコードする。
  // これでH.264の3840x2160という上限がなくなる。
  bool hevc = false;
  // hevcと併用。代わりに4:2:0を求め（VideoSettingsのfield 8でbit 3を立てない）、
  // H.264と同じくadapter_indexのGPUでlibavcodec + D3D11VAによりデコードする。
  // HEVC 4:4:4に対応しないGPU（AMD）でもこれならデコードできる。
  bool hevc420 = false;
};

struct SessionStats {
  uint64_t video_packets = 0;
  uint64_t video_bytes = 0;
  uint64_t lost_packets = 0;      // シーケンスの抜け（NACKで直す前）
  uint64_t dropped_frames = 0;    // あきらめたアクセスユニット
  uint64_t frames_decoded = 0;
  uint64_t nacks_sent = 0;
  uint64_t keyframe_requests = 0;
  uint64_t queue_drops = 0;
  uint64_t unknown_ssrc_packets = 0;  // 自分のSSRCグループ以外のビデオパケット
  uint64_t ctrl_rtcp = 0;             // UDP 5900に来たホストのRTCP
  uint64_t video_rtcp = 0;            // ビデオのポートに来たホストのRTCP
  uint64_t ctrl_other = 0;            // UDP 5900に来たホストの音声RTP
  uint64_t tcp_messages = 0;          // ホストから来た制御チャネルのメッセージ（復号後）
  uint64_t pointer_events = 0;        // 送った数
  uint64_t key_events = 0;            // 送った数
  uint64_t repaired_frames = 0;       // しばらく欠けていて、あとでそろったもの
  uint64_t late_after_drop = 0;       // あきらめたユニットのパケット
  uint64_t cursor_updates = 0;
  uint64_t skipped_pictures = 0;      // HEVC: 失ったピクチャを参照するためデコードしなかったもの
  uint64_t ltr_acks = 0;
  bool waiting_for_keyframe = true;   // どれかのビデオストリームが待っている
  std::string decoder = "-";
};

class Session {
 public:
  explicit Session(SessionOptions opt);
  ~Session();
  Session(const Session&) = delete;
  Session& operator=(const Session&) = delete;

  // ブロックする（数秒。SessionSelectのポップアップがMacでのクリックを待つ間は
  // 最大1分）。失敗したら例外を投げる。成否にかかわらずパスワードは消す。
  void connect();
  void stop();

  // 制御チャネルが切れたか、ワーカーが失敗したらfalse。
  bool alive() const { return alive_; }
  std::string failure() const;

  // ポインタの座標空間。メインディスプレイのエンコーダのキャンバスか、ディスプレイが
  // 2台のとき（またはレイアウトを受け取ったあと）は全ディスプレイにまたがるバッキングキャンバス。
  int canvas_width() const { return canvas_w_; }
  int canvas_height() const { return canvas_h_; }
  // 接続後のビデオストリーム（ディスプレイ）の数。1、display2があれば2。
  int video_streams() const { return static_cast<int>(streams_.size()); }
  // ストリームのピクチャを分ける横帯の数（HEVCは4で、帯ごとに別のフレーム。
  // H.264は1）。帯iはキャンバスのi × 帯の高さの行から始まる。
  int tiles() const { return tiles_; }
  // 前回の呼び出し以降の、1本のストリームのタイルごとの最新デコード済みフレーム。
  std::vector<media::VideoFrame> take_frames(int stream = 0);
  // バッキングキャンバス上の各ディスプレイの矩形（AppleDisplayLayout）。並びは
  // ディスプレイを要求した順。最初のレイアウトを受け取るまでは空。
  std::vector<rfb::DisplayRect> display_rects() const;
  // これまでに受け取ったAppleDisplayLayoutの数。Macが解像度の要求に答えたときや、
  // Mac自身がディスプレイを変えたときに1つ増える。
  uint64_t layouts_received() const { return n_layouts_; }
  // 標準モードでは、画面はビデオフレームではなく32ビットのキャンバスになる。
  bool standard_mode() const { return !opt_.media; }
  // 前回の呼び出し以降にキャンバスのどこかが変わっていれば、キャンバスを
  // （そのロックを取ったまま）渡して`draw`を呼ぶ。何も変わっていなければfalse。
  bool take_fb_update(const std::function<void(const uint32_t* pixels, int width, int height,
                                               const std::vector<FbRect>& dirty)>& draw);
  // 前回の呼び出し以降に変わっていれば、ホストのカーソルの形を返す。形がnullなら
  // 既定の矢印。legacy_cursorのときは使わない。
  std::optional<CursorRef> take_cursor();
  // Macのディスプレイの1ポイントあたりのキャンバスのピクセル数（Retinaなら2。
  // ディスプレイのレイアウトから求め、最初のレイアウトまでは要求したスケール）。
  // カーソルの形はポイント単位で届くので、この倍率で大きく描く。
  float pixels_per_point() const;

  // 入力。座標はキャンバスのピクセル。どのスレッドから呼んでもよい。
  void send_key(bool down, uint32_t keysym);
  void send_pointer(uint8_t buttons, int x, int y);
  void request_keyframe();
  // 動的解像度。セッションの途中で仮想ディスプレイの新しいジオメトリ（0x1d）を送る。
  // ディスプレイが2台なら両方に送る。ホストはAppleDisplayLayoutで答える。ジオメトリが
  // 変わったら、エンコーダが新しいサイズで始め直すようにメディアストリーム（0x1c）を
  // 提示し直し、新しいストリームに切り替える。
  void request_resolution(const rfb::VirtualDisplayParams& display,
                          const std::optional<rfb::VirtualDisplayParams>& display2 = std::nullopt);
  // 標準モードで、セッションの途中に画質を変える。SetEncodingsを送り直して全体の
  // 更新を要求する。画面全体はリストのうちホストが対応する最初のエンコーディングで
  // 送り直され、以後の更新もそのエンコーディングになる。
  void set_encodings(const std::vector<int32_t>& encodings);

  SessionStats stats() const;

 private:
  using Clock = std::chrono::steady_clock;

  struct SeqState {
    uint16_t max_seq = 0;
    uint32_t roc = 0;
  };
  struct RxPacket {
    Bytes data;
    Clock::time_point at;  // ソケットから取り出した時刻
  };
  // 1枚のピクチャの最初と最後のパケットをソケットから取り出した時刻（--perf）。
  struct AuArrival {
    Clock::time_point first, last;
  };

  // 1本のビデオストリーム（仮想ディスプレイ1台分）。UDPのポートと鍵、SSRC
  // グループ、RTPのグループ分け、デコーダ、最新フレームを持つ。ストリーム0は
  // メインディスプレイ（port + 1）、ストリーム1は2台目（port + 2）。
  struct VideoStream {
    int index = 0;
    uint16_t port = 0;
    net::UdpSocket sock;
    uint32_t our_ssrc = 0;  // 自分の提示から取る。自分が送るフィードバックの送信者SSRC
    std::unique_ptr<proto::SrtpDecryptor> dec;
    std::unique_ptr<proto::SrtcpEncryptor> srtcp;

    // video-rx → video
    std::mutex q_mu;
    std::condition_variable q_cv;
    std::deque<RxPacket> q;

    // videoスレッドの状態。
    media::VideoDecoder decoder;
    Bytes sps, pps;  // ストリームのH.264の設定が届くまでは空
    // HEVC（--hevc）では上のsps / ppsはHEVCのもので、VPSも持つ。新しいものが届いたら
    // （Macがエンコーダを始め直した。リサイズや、2台目のディスプレイの最初のストリーム）
    // 3つそろった時点でデコーダを開き直す。
    Bytes vps;
    bool hevc_reopen = false;
    bool hevc_opened = false;
    // HEVC 4:2:0では、ピクチャを失ってもおかしくなるのはその帯だけなので、デコーダは
    // そのままにする。失ったピクチャを参照するピクチャは、Macがその帯をリフレッシュ
    // するまでデコードしない（表示もしない）。問題のないピクチャはDONLで確認応答を
    // 返す（LTR ack）。
    media::HevcRefTracker refs;
    std::optional<uint16_t> last_donl;  // 最後にそろったピクチャのもの
    std::map<uint32_t, uint16_t> last_pkt_pic;  // SSRCごとの、最後のパケットのピクチャ番号
    Clock::time_point last_loss_seen{};  // DONLの抜け。ピクチャを丸ごと失うとほかに痕跡が残らない
    // --perf（ストリーム0）。帯ごとに、失ったピクチャのせいで古いままになった時刻。
    std::map<int, Clock::time_point> stale_since;
    std::unique_ptr<RtpGrouper> grouper;
    std::map<uint32_t, uint64_t> unknown_counts;
    // 自分のグループ以外のSSRCから来たパケット。新しいストリームに乗り換えるとき、
    // 次のキーフレームを待たずにその始まり（H.264の設定とキーフレーム）を
    // 流し直せるように取っておく。
    std::map<uint32_t, std::deque<proto::RtpPacket>> unknown_packets;
    // この時刻までは、自分のグループが途切れたらすぐに新しいSSRCグループに乗り換える。
    // 接続直後とリサイズの直後は、ホストが新しいストリームを始めるため。
    std::atomic<int64_t> fast_adopt_until_ms{0};
    Clock::time_point last_mapped{}, last_adoption{};

    // videoスレッドとtxスレッドで共有する（Session::state_mu_で守る）。
    std::map<uint32_t, int> ssrc_to_tile;
    std::map<uint32_t, SeqState> seq;
    std::map<uint32_t, std::set<uint16_t>> nack_pending;

    // UIスレッドに渡すデコード済みフレーム（Session::frame_mu_で守る）。そろった
    // ピクチャを`latest`に入れる。アセンブラの期限はUIスレッドも描画のたびに確かめる。
    std::unique_ptr<PictureAssembler> assembler;
    std::map<int, media::VideoFrame> latest;

    std::atomic<bool> keyframe_wanted{true};
    std::atomic<bool> keyframe_now{false};  // すぐに送る。間隔もアイドルの確認も無視する
    std::atomic<bool> waiting_key{true};
    std::atomic<uint64_t> frames_since_key{0}, repaired{0};
    std::atomic<int64_t> last_packet_ms{0};  // steady-clockのms。0はまだないこと
    std::atomic<int64_t> last_frame_ms{0};
    std::atomic<int64_t> last_refresh_ms{0};  // キーフレーム要求を送った時刻
    std::atomic<bool> answer_seen{false};     // その後にIDR / キーフレームが届き始めた
    // 最新のIDR / キーフレームのピクチャ番号（-1はまだない）と、その最初のパケットが
    // 届いた時刻。それより前に失ったものは、そのIDRでリフレッシュされている。
    std::atomic<int> last_idr_pic{-1};
    Clock::time_point last_idr_at{};  // videoスレッドが使う
    // MacはIDRを送っている最中に届いた要求を無視する。そのため、この時刻
    // （steady-clockのms）までは要求を送らない。
    std::atomic<int64_t> refresh_not_before_ms{0};
    std::string decoder_name = "-";  // Session::info_mu_で守る

    // txスレッド
    Clock::time_point last_kf_request{}, last_reanchor{};
    bool first_kf_request = true;
  };

  proto::ConnectOptions connect_options() const;
  void negotiate_and_wait_for_burst();
  void connect_framebuffer();
  void fb_tx_loop();
  std::vector<proto::RtpPacket> collect_burst();
  void make_grouper(VideoStream& s);
  RtpGrouper::Timing repair_timing() const;
  void fail(const std::string& why);

  std::optional<RxPacket> pop_video(VideoStream& s, int timeout_ms);
  void video_rx_loop(VideoStream& s);
  void video_loop(VideoStream& s, std::vector<proto::RtpPacket> burst);
  // `rx`はパケットをソケットから取り出した時刻。
  void handle_rtp(VideoStream& s, proto::RtpPacket&& pkt, Clock::time_point rx);
  void on_access_unit(VideoStream& s, uint32_t ssrc, uint32_t ts, std::vector<Bytes>&& payloads);
  // アセンブラの出力 → `latest`。frame_mu_を取ったまま呼ぶ。
  void show_frames_locked(VideoStream& s, std::vector<media::VideoFrame>&& frames);
  // 1枚のピクチャのペイロードをデコーダに入れる。デコードするものがなければ
  // （スライスがない、またはパラメータセットがまだない）false。
  bool decode_avc_unit(VideoStream& s, int tile, uint32_t ts, const std::vector<Bytes>& payloads,
                       std::vector<media::VideoFrame>& frames, bool& key);
  // 4:4:4ならQSV、4:2:0ならストリームのパラメータセットを使うlibavcodec。
  void open_hevc_decoder(VideoStream& s);
  bool decode_hevc_unit(VideoStream& s, int tile, uint32_t ts, const std::vector<Bytes>& payloads,
                        std::vector<media::VideoFrame>& frames, bool& key);
  std::string perf_line();
  std::string stale_summary();
  // `seq`より前のパケットが欠けていればtrue。
  bool track_seq(VideoStream& s, uint32_t ssrc, uint16_t seq);
  void on_packet_gap(VideoStream& s, uint32_t ssrc, std::optional<uint16_t> pic);
  void maybe_adopt_ssrcs(VideoStream& s, Clock::time_point now);
  void ctrl_rx_loop();
  void tcp_rx_loop();
  void handle_fbu(const Bytes& msg);
  void apply_pixels(const FbuEvents& ev);
  void reoffer_media(const std::string& why);
  void fast_adopt_all();
  void send_control(const Bytes& msg);
  void tx_loop();
  void tx_stream(VideoStream& s, int tick, bool periodic);
  std::chrono::milliseconds retry_interval() const;
  // ストリーム0のものはUDP 5900に送る（Pythonクライアントがフィードバックをすべて
  // 送る先）。2本目のストリームのものは自分のポートにも送る。`also_video_port`なら
  // ストリーム0のものを5901にも送る（ホストがビデオストリーム自身のRTCPを多重化する先）。
  void send_rtcp(VideoStream& s, const Bytes& rtcp, bool also_video_port = false);
  void send_keyframe_request(VideoStream& s);
  // きれいにデコードできたピクチャのDONLを載せたAPPのLTR ack（PT 204、subtype 5）を、
  // session.pyと同じくストリーム自身のポートに送る。
  void send_ltr_ack(VideoStream& s, uint16_t donl);
  // `tile`のピクチャが画面に出たので、その帯の古いままの期間を終える（--perf）。
  void note_strip_shown(VideoStream& s, int tile);
  void wake_tx();
  void firewall_punch_loop();
  // ISS_RTP_DUMP=<file>: ストリーム0のビデオRTP（ヘッダは受け取ったまま、ペイロードは
  // 復号後）と自分のRTCPフィードバック（SRTCPにする前）を、時刻付きで書き出す。
  // tools/rtp_dump.py用。ISS_LOSS_PERMILLE=<n>: ストリーム0のビデオパケットのうち
  // その割合を復号後に捨てる。損失のない経路で損失からの立ち直りを試すため。
  enum class DumpKind : uint8_t { Rx = 0, Tx = 1, Lost = 2 };
  void dump_packet(DumpKind kind, const uint8_t* head, size_t head_len, const Bytes& body, Clock::time_point at);
  bool test_loss();

  SessionOptions opt_;
  net::Address dest_;  // 標準モードでは.textだけを使う（指定されたままのホスト）
  uint16_t ctrl_port_ = 0;
  net::UdpSocket sock_ctrl_;
  std::mutex send_mu_;  // stop()の途中に入力を送ってneg_に触れないように守る
  std::optional<proto::NegotiationResult> neg_;
  uint32_t our_audio_ssrc_ = 0;
  int tiles_ = 1;
  std::atomic<int> canvas_w_{0}, canvas_h_{0};
  std::vector<std::unique_ptr<VideoStream>> streams_;

  std::unique_ptr<proto::SrtpEncryptor> audio_enc_;

  // --perf（ストリーム0）。ピクチャごとの値（ms）で、RTPタイムスタンプの間隔（Macが
  // エンコードした間隔）、ソケット上でピクチャがそろう間隔、最初 → 最後のパケット、
  // 最後のパケット → videoスレッドが取り出すまで、デコード（GPU → CPUのコピーを
  // 含む）、サイズ（KB）。それと、UIが取る前に置き換わったピクチャの数。
  std::map<uint32_t, AuArrival> au_rx_;  // RTPタイムスタンプがキー。videoスレッドが使う
  std::optional<uint32_t> perf_last_ts_;
  Clock::time_point perf_last_complete_{};
  PerfStat perf_rtp_step_, perf_arrival_step_, perf_spread_, perf_wait_, perf_decode_, perf_kb_;
  // 帯で最初に失ったピクチャ（その最初のパケット） → その帯の次のピクチャが
  // 画面に出るまで。
  PerfStat perf_stale_;
  std::atomic<uint64_t> n_replaced_{0};

  // 標準モードの画面。tcp-rxが書き、UIが読む。
  std::mutex fb_mu_;
  Framebuffer fb_;
  std::atomic<uint64_t> n_fb_errors_{0};

  std::mutex rtp_dump_mu_;
  std::FILE* rtp_dump_ = nullptr;
  Clock::time_point rtp_dump_t0_{};
  uint32_t loss_permille_ = 0;
  uint64_t loss_rng_ = 0x9E3779B97F4A7C15ull;  // ストリーム0のvideoスレッドが使う

  // tcp-rxスレッドの状態。最新のカーソルはpending_cursor_でUIを待つ。
  std::FILE* dump_ = nullptr;
  CursorCache cursor_cache_;
  mutable std::mutex layout_mu_;  // layout_はUIが読む（display_rects）
  std::optional<DisplayLayoutInfo> layout_;
  std::atomic<float> layout_scale_{0};  // 最後のレイアウトのバッキング / ポイント。0はまだないこと
  std::atomic<uint64_t> n_layouts_{0};
  std::mutex cursor_mu_;
  std::optional<CursorRef> pending_cursor_;

  // videoスレッドとtxスレッドで共有するもの。各ストリームのSSRCの状態。
  mutable std::mutex state_mu_;
  // UIスレッドに渡すデコード済みフレーム。各ストリームの`latest`。
  mutable std::mutex frame_mu_;

  // ポインタイベント（send_mu_で守る）。ISS_POINTERの実験用。
  enum class PointerMode { Msg10, Rfb, Time, Clicks };
  PointerMode pointer_mode_ = PointerMode::Msg10;
  int64_t pointer_t0_ms_ = 0;
  uint8_t pointer_prev_buttons_ = 0, pointer_last_button_ = 0;
  uint32_t pointer_clicks_ = 0;
  int64_t pointer_last_down_ms_ = 0;
  int pointer_last_x_ = 0, pointer_last_y_ = 0;

  // 標準モードのピクチャの状態（メディアモードではストリームごとに持つ）。
  std::atomic<int64_t> last_frame_ms_{0};
  std::atomic<bool> waiting_key_{true};
  std::atomic<int64_t> last_ctrl_rx_ms_{0};  // UDP 5900に来たMacの音声 / RTCP
  std::atomic<uint64_t> n_media_reoffers_{0};

  std::atomic<uint64_t> n_packets_{0}, n_bytes_{0}, n_lost_{0}, n_dropped_{0}, n_frames_{0};
  std::atomic<uint64_t> n_nacks_{0}, n_kf_requests_{0}, n_queue_drops_{0};
  std::atomic<uint64_t> n_unknown_{0}, n_ctrl_rtcp_{0}, n_ctrl_other_{0}, n_tcp_msgs_{0}, n_pointer_{0}, n_keys_{0};
  std::atomic<uint64_t> n_late_{0}, n_cursor_{0}, n_video_rtcp_{0};
  std::atomic<uint64_t> n_skipped_{0}, n_ltr_acks_{0};  // HEVC 4:2:0: 損失後に飛ばしたピクチャ、送ったack
  // ISS_LTR_ACK: "0"なら何も送らない。"tile0"なら帯0のものだけ（Pythonクライアント
  // と同じ）。それ以外なら問題のないピクチャすべてについて送る。
  enum class LtrAck { Off, Tile0, All } ltr_ack_ = LtrAck::All;
  // リフレッシュ要求（HEVC 4:2:0）の実験用の調整値。ISS_REFRESHが
  // "pli" / "fir" / "legacy"ならその種類だけを送り、"none"なら何も送らない（既定は
  // 3種類すべて）。
  // ISS_REFRESH_TARGET=allなら、タイル0だけでなく全部の帯のSSRCに宛てる。
  bool refresh_pli_ = true, refresh_fir_ = true, refresh_legacy_ = true, refresh_all_ssrcs_ = false;
  // ピクチャ`last`（その番号。分からなければnullopt）と、場合によってはそれより前の
  // いくつかが、そろって届かなかった。それをカバーするリフレッシュが進行中でなければ要求する。
  void on_pictures_lost(VideoStream& s, std::optional<uint16_t> last);
  mutable std::mutex info_mu_;
  std::string decoder_name_ = "-";  // 標準モードのコーデック
  std::string failure_;

  std::mutex tx_mu_;
  std::condition_variable tx_cv_;
  bool tx_wake_ = false;

  std::atomic<bool> stop_{false};
  std::atomic<bool> punching_{false};
  std::atomic<bool> alive_{false};
  std::vector<std::thread> threads_;
  std::thread punch_thread_;
};

}  // namespace iss::session
