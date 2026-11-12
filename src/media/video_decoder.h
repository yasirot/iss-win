// FFmpegのC APIを使う映像デコーダー（hevc.pyのデコード部分の移植）。
//
// コーデックコンテキストは全タイルで1つだけ共有する。Appleのタイルはほかの
// タイルのピクチャを参照するので、タイルごとにコンテキスト（別々のDPB）を
// 持つとデコード結果がでたらめになる。全タイルのNALUを同じコンテキストに通し、
// 出てきたフレームは入力時に付けたPTSで元のタイルに振り分ける。
//
// まずD3D11VA（選んだDXGIアダプター上）を試し、だめならソフトウェアの
// libavcodecを使う。アクセラレーターが本当に使われたかは、openの成否ではなく
// 最初に出てきたフレームのピクセル形式で判断する。GPUがそのプロファイルに
// 対応していないと（多いのはHEVC 4:4:4）、FFmpegは知らせずにソフトウェアで
// デコードするためだ。
#pragma once

#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "core/bytes.h"

struct AVCodecContext;
struct AVFrame;
struct AVBufferRef;
struct SwsContext;

namespace iss::media {

enum class Codec { Hevc, H264 };

// CPUメモリ上のデコード済みピクチャ。PlanarはY/U/Vの3プレーン。Biplanar（NV12）は
// Yプレーンと、UVを交互に並べたプレーン1つ（plane(2)はnull）。Packed（QSVの
// 4:4:4から来るVUYX）は1プレーンで、1画素4バイトをV, U, Y, 未使用の順に並べる。
struct VideoFrame {
  enum class Layout { Planar, Biplanar, Packed };
  enum class Range { Unspecified, Limited, Full };

  std::shared_ptr<AVFrame> av;  // プレーンを所有する
  int tile = 0;
  uint32_t rtp_ts = 0;  // decode()に渡された値。Macの1枚の画面のタイルはこれが共通
  int width = 0, height = 0;
  int chroma_width = 0, chroma_height = 0;
  Layout layout = Layout::Planar;
  Range range = Range::Unspecified;  // ビットストリームのVUIから取る
  bool had_error = false;  // libavがconcealmentや破損の印を付けた
  // セッションが設定する。ピクチャの最後のパケットをソケットから受け取った時刻
  // （--perfの遅延計測用）。
  std::chrono::steady_clock::time_point received{};

  const uint8_t* plane(int i) const;
  int stride(int i) const;
  bool is_yuv444() const { return chroma_width == width && chroma_height == height; }
};

class VideoDecoder {
 public:
  struct Options {
    Codec codec = Codec::Hevc;
    bool prefer_hwaccel = true;
    int adapter_index = -1;  // D3D11VAに使うDXGIアダプター。-1は既定のデバイス
    // HEVC専用。libavcodecの代わりにIntel Quick Sync（hevc_qsv）を使い、
    // decode_au()でアクセスユニットを丸ごと渡す。WindowsでAppleのHEVC 4:4:4を
    // ハードウェアでデコードできる唯一の経路。Intel GPUはQSVが自分で選ぶ。
    bool qsv = false;
  };

  VideoDecoder();
  ~VideoDecoder();
  VideoDecoder(const VideoDecoder&) = delete;
  VideoDecoder& operator=(const VideoDecoder&) = delete;

  // `extradata` はAnnex-B形式のパラメータセット（VPS/SPS/PPSかSPS/PPS）。
  // どのデコーダーも開けないときはstd::runtime_errorを投げる。
  void open(const Options& opt, const Bytes& extradata);
  void close();

  // NALUを1つ渡す（スタートコードなし）。デコードできたフレームは `out` に追加する。
  void decode(const Bytes& nalu, int tile, std::vector<VideoFrame>& out, uint32_t rtp_ts = 0);
  // QSV用。1タイル分のピクチャをAnnex-Bのアクセスユニットで渡す（キーフレームでは
  // パラメータセットを先頭に置く）。`key` はIRAPスライスを含むかどうか。
  void decode_au(const Bytes& annexb, int tile, bool key, std::vector<VideoFrame>& out, uint32_t rtp_ts = 0);
  void flush(std::vector<VideoFrame>& out);

  // アクセラレーターが使われていると確かめられたら"d3d11va"、それ以外は"software"。
  std::string backend() const;
  // 最初のIRAP/IDRを渡すまではtrue（それより前のPフレームは捨てる）。
  bool waiting_for_keyframe() const { return !seen_keyframe_ || reset_pending_; }
  uint64_t dropped_pre_keyframe() const { return pre_key_drops_; }

  // フレームが失われたり捨てられたりしたあとに呼ぶ。次のキーフレームまでインター
  // スライスを捨て、そのキーフレームでコーデックコンテキストを作り直して空のDPBから
  // 始める。AppleのH.264のキーフレームはIDRでないIスライスなので、それだけでは
  // おかしくなったlibavのDPBが空にならない。
  void reset_on_next_keyframe() { reset_pending_ = true; }
  // 上と同じだが、コンテキストを今すぐ作り直す。どちらの場合も、次のキーフレーム
  // まではインタースライスを捨てる。
  void reset_now();

 private:
  bool open_context(bool hw, const Bytes& extradata);
  void open_qsv();
  void send(const uint8_t* data, size_t size, bool start_code, int tile, uint32_t rtp_ts, std::vector<VideoFrame>& out);
  void receive_frames(std::vector<VideoFrame>& out);
  bool to_video_frame(AVFrame* f, VideoFrame& vf);

  Options opt_;
  Bytes extradata_;
  bool reset_pending_ = false;
  AVCodecContext* ctx_ = nullptr;
  AVBufferRef* hw_device_ = nullptr;
  SwsContext* sws_ = nullptr;
  bool hw_requested_ = false;
  bool hw_bound_ = false;
  bool hw_verified_ = false;
  bool seen_keyframe_ = false;
  uint64_t pre_key_drops_ = 0;
  int64_t next_pts_ = 0;
  struct Origin {
    int tile;
    uint32_t rtp_ts;
  };
  std::map<int64_t, Origin> pts_origin_;
};

// Annex-Bのバイト列（3バイトか4バイトのスタートコード）をNALUに分ける。
std::vector<Bytes> split_annexb(const Bytes& stream);

}  // namespace iss::media
