#include "media/video_decoder.h"

extern "C" {
#include <libavcodec/avcodec.h>
#include <libavutil/hwcontext.h>
#include <libavutil/imgutils.h>
#include <libavutil/pixdesc.h>
#include <libswscale/swscale.h>
}

#include <cstring>
#include <format>
#include <stdexcept>

#include "core/log.h"
#include "media/bitstream.h"
#include "media/nalu.h"

namespace iss::media {
namespace {

constexpr uint8_t kStartCode[4] = {0, 0, 0, 1};
constexpr size_t kPtsMapSoftMax = 4000;
constexpr int64_t kPtsMapPruneKeep = 2000;

std::string av_err(int rc) {
  char buf[AV_ERROR_MAX_STRING_SIZE] = {};
  av_strerror(rc, buf, sizeof(buf));
  return buf;
}

// get_format。デコーダーがD3D11を出してきたらそれを選び（ハードウェアを
// 求めたときだけ）、そうでなければ最初のソフトウェア形式を選ぶ。
AVPixelFormat pick_format(AVCodecContext* ctx, const AVPixelFormat* fmts) {
  const bool want_hw = ctx->opaque && *static_cast<bool*>(ctx->opaque);
  if (want_hw) {
    for (const AVPixelFormat* p = fmts; *p != AV_PIX_FMT_NONE; ++p) {
      if (*p == AV_PIX_FMT_D3D11) return *p;
    }
  }
  for (const AVPixelFormat* p = fmts; *p != AV_PIX_FMT_NONE; ++p) {
    const AVPixFmtDescriptor* d = av_pix_fmt_desc_get(*p);
    if (d && !(d->flags & AV_PIX_FMT_FLAG_HWACCEL)) return *p;
  }
  return AV_PIX_FMT_NONE;
}

// HEVCでlibavcodecに渡すのは、ピクチャの先頭になるスライスのNALU（type 0..31、
// first_slice_segment_in_pic_flag）だけ。パラメータセットはextradataで渡す。
bool hevc_decodable(const Bytes& nalu) {
  return nalu.size() >= 3 && hevc_nal_type(nalu[0]) <= 31 && (nalu[2] & 0x80);
}

}  // namespace

bool avc_nal_is_keyframe(const Bytes& nalu) {
  if (nalu.size() < 2) return false;
  const int t = avc_nal_type(nalu[0]);
  if (t == AVC_NAL_SLICE_IDR) return true;
  if (t != AVC_NAL_SLICE_NONIDR) return false;
  Bytes rbsp = remove_emulation_prevention(nalu.data() + 1, nalu.size() - 1);
  BitReader br(rbsp);
  br.read_ue();  // first_mb_in_slice
  uint64_t slice_type = br.read_ue();
  return slice_type == 2 || slice_type == 7;
}

// ── VideoFrame ───────────────────────────────────────────────────────────

const uint8_t* VideoFrame::plane(int i) const {
  if (!av || i < 0 || i > 2) return nullptr;
  if ((layout == Layout::Biplanar && i == 2) || (layout == Layout::Packed && i > 0)) return nullptr;
  return av->data[i];
}

int VideoFrame::stride(int i) const {
  if (!av || i < 0 || i > 2) return 0;
  return av->linesize[i];
}

// ── VideoDecoder ─────────────────────────────────────────────────────────

VideoDecoder::VideoDecoder() = default;
VideoDecoder::~VideoDecoder() { close(); }

void VideoDecoder::close() {
  if (ctx_) avcodec_free_context(&ctx_);
  if (hw_device_) av_buffer_unref(&hw_device_);
  if (sws_) {
    sws_freeContext(sws_);
    sws_ = nullptr;
  }
  hw_bound_ = hw_verified_ = seen_keyframe_ = false;
  pre_key_drops_ = 0;
  next_pts_ = 0;
  pts_origin_.clear();
}

bool VideoDecoder::open_context(bool hw, const Bytes& extradata) {
  const AVCodec* codec = avcodec_find_decoder(opt_.codec == Codec::Hevc ? AV_CODEC_ID_HEVC : AV_CODEC_ID_H264);
  if (!codec) throw std::runtime_error("FFmpeg build has no HEVC/H.264 decoder");

  ctx_ = avcodec_alloc_context3(codec);
  if (!ctx_) throw std::bad_alloc();
  ctx_->extradata = static_cast<uint8_t*>(av_mallocz(extradata.size() + AV_INPUT_BUFFER_PADDING_SIZE));
  std::memcpy(ctx_->extradata, extradata.data(), extradata.size());
  ctx_->extradata_size = static_cast<int>(extradata.size());
  ctx_->flags |= AV_CODEC_FLAG_LOW_DELAY;  // 並べ替えのためにためない
  ctx_->flags2 |= AV_CODEC_FLAG2_FAST;     // ライブ映像ならbitexactでない高速処理で構わない
  // SLICEスレッドは遅延も並べ替えも増やさずにフレーム内で並列に処理する。
  // FRAMEスレッドにすると、タイルをまたぐ参照の順序が崩れる。
  ctx_->thread_type = FF_THREAD_SLICE;
  ctx_->thread_count = 0;

  hw_requested_ = false;
  if (hw) {
    std::string dev = opt_.adapter_index >= 0 ? std::to_string(opt_.adapter_index) : std::string();
    int rc = av_hwdevice_ctx_create(&hw_device_, AV_HWDEVICE_TYPE_D3D11VA, dev.empty() ? nullptr : dev.c_str(),
                                    nullptr, 0);
    if (rc < 0) {
      log::info("d3d11va device unavailable: {}", av_err(rc));
      avcodec_free_context(&ctx_);
      return false;
    }
    ctx_->hw_device_ctx = av_buffer_ref(hw_device_);
    hw_requested_ = true;
  }
  ctx_->opaque = &hw_requested_;
  ctx_->get_format = pick_format;

  int rc = avcodec_open2(ctx_, codec, nullptr);
  if (rc < 0) {
    log::info("{} decoder open failed: {}", hw ? "d3d11va" : "software", av_err(rc));
    avcodec_free_context(&ctx_);
    if (hw_device_) av_buffer_unref(&hw_device_);
    hw_requested_ = false;
    return false;
  }
  return true;
}

// extradataは渡さない。hevc_qsvは最初のキーフレームのアクセスユニットにある
// パラメータセットから画面サイズを決める（Annex-Bのextradataを渡すと0x0になる）。
// Python版のqsvhevc.pyで、async_depthは2が、遅延と4タイル60 fpsへの追従の
// 釣り合いがよかった。
void VideoDecoder::open_qsv() {
  const AVCodec* codec = avcodec_find_decoder_by_name("hevc_qsv");
  if (!codec) throw std::runtime_error("FFmpeg build has no hevc_qsv decoder");
  ctx_ = avcodec_alloc_context3(codec);
  if (!ctx_) throw std::bad_alloc();
  ctx_->flags |= AV_CODEC_FLAG_LOW_DELAY;
  AVDictionary* o = nullptr;
  av_dict_set(&o, "async_depth", "2", 0);
  av_dict_set(&o, "gpu_copy", "on", 0);
  const int rc = avcodec_open2(ctx_, codec, &o);
  av_dict_free(&o);
  if (rc < 0) {
    avcodec_free_context(&ctx_);
    throw std::runtime_error("hevc_qsv could not be opened (no Intel GPU with Quick Sync?): " + av_err(rc));
  }
  log::info("HEVC decoder: hevc_qsv (Intel Quick Sync)");
}

void VideoDecoder::open(const Options& opt, const Bytes& extradata) {
  close();
  opt_ = opt;
  extradata_ = extradata;
  reset_pending_ = false;
  if (opt.qsv) {
    open_qsv();
    return;
  }
  if (opt.prefer_hwaccel && open_context(true, extradata)) {
    log::info("{} decoder: d3d11va requested (adapter {})", opt.codec == Codec::Hevc ? "HEVC" : "H.264",
              opt.adapter_index);
    return;
  }
  if (!open_context(false, extradata)) throw std::runtime_error("could not open a software video decoder");
  log::info("{} decoder: software", opt.codec == Codec::Hevc ? "HEVC" : "H.264");
}

void VideoDecoder::reset_now() {
  if (!ctx_) return;
  const Options o = opt_;
  const Bytes extradata = extradata_;
  open(o, extradata);
}

std::string VideoDecoder::backend() const { return opt_.qsv ? "qsv" : hw_bound_ ? "d3d11va" : "software"; }

// QSVはタイルをまたいで自前のDPBを持つ。ストリームの途中でセッションを閉じると
// ネイティブコードで落ちたことがある（qsvhevc.py）。そのため、リセットでは
// 次のキーフレームでDPBが始め直されるまでピクチャを捨てるだけにする。
void VideoDecoder::decode_au(const Bytes& annexb, int tile, bool key, std::vector<VideoFrame>& out, uint32_t rtp_ts) {
  if (!ctx_ || annexb.empty()) return;
  if (reset_pending_) {
    if (!key) {
      ++pre_key_drops_;
      return;
    }
    reset_pending_ = false;
  }
  if (key) {
    seen_keyframe_ = true;
  } else if (!seen_keyframe_) {
    ++pre_key_drops_;
    return;
  }
  send(annexb.data(), annexb.size(), false, tile, rtp_ts, out);
}

void VideoDecoder::decode(const Bytes& nalu, int tile, std::vector<VideoFrame>& out, uint32_t rtp_ts) {
  if (!ctx_ || nalu.empty()) return;

  bool is_key = false;
  if (opt_.codec == Codec::Hevc) {
    if (!hevc_decodable(nalu)) return;
    is_key = hevc_is_irap(hevc_nal_type(nalu[0]));
  } else {
    const int t = avc_nal_type(nalu[0]);
    if (t == AVC_NAL_SPS || t == AVC_NAL_PPS) return;  // extradataで渡し済み
    is_key = avc_nal_is_keyframe(nalu);
  }
  if (reset_pending_) {
    if (!is_key) {
      ++pre_key_drops_;
      return;
    }
    const Options o = opt_;
    const Bytes extradata = extradata_;
    open(o, extradata);  // 新しいコンテキストと空のDPB。reset_pending_も下ろす
    log::info("decoder rebuilt on a keyframe after a broken reference chain");
  }
  if (is_key) {
    seen_keyframe_ = true;
  } else if (!seen_keyframe_) {
    ++pre_key_drops_;  // DPBが空なので、出力はconcealmentで埋めた絵になる
    return;
  }

  send(nalu.data(), nalu.size(), true, tile, rtp_ts, out);
}

void VideoDecoder::send(const uint8_t* data, size_t size, bool start_code, int tile, uint32_t rtp_ts,
                        std::vector<VideoFrame>& out) {
  const size_t prefix = start_code ? 4 : 0;
  AVPacket* pkt = av_packet_alloc();
  if (!pkt || av_new_packet(pkt, static_cast<int>(size + prefix)) < 0) {
    av_packet_free(&pkt);
    return;
  }
  if (start_code) std::memcpy(pkt->data, kStartCode, 4);
  std::memcpy(pkt->data + prefix, data, size);
  const int64_t pts = next_pts_++;
  pkt->pts = pkt->dts = pts;
  pts_origin_[pts] = {tile, rtp_ts};
  if (pts_origin_.size() > kPtsMapSoftMax) {
    pts_origin_.erase(pts_origin_.begin(), pts_origin_.lower_bound(pts - kPtsMapPruneKeep));
  }

  int rc = avcodec_send_packet(ctx_, pkt);
  if (rc == AVERROR(EAGAIN)) {  // 出力キューが満杯。取り出してから1回だけやり直す
    receive_frames(out);
    rc = avcodec_send_packet(ctx_, pkt);
  }
  av_packet_free(&pkt);
  if (rc < 0 && rc != AVERROR(EAGAIN)) {
    // 損失のあるストリームではよくある。このptsのフレームはもう出てこない。
    pts_origin_.erase(pts);
    log::debug("decode error (tile {}): {}", tile, av_err(rc));
  }
  receive_frames(out);
}

void VideoDecoder::flush(std::vector<VideoFrame>& out) {
  if (!ctx_) return;
  avcodec_send_packet(ctx_, nullptr);
  receive_frames(out);
  avcodec_flush_buffers(ctx_);
}

void VideoDecoder::receive_frames(std::vector<VideoFrame>& out) {
  for (;;) {
    AVFrame* f = av_frame_alloc();
    int rc = avcodec_receive_frame(ctx_, f);
    if (rc < 0) {
      av_frame_free(&f);
      return;
    }
    VideoFrame vf;
    if (to_video_frame(f, vf)) out.push_back(std::move(vf));
  }
}

bool VideoDecoder::to_video_frame(AVFrame* f, VideoFrame& vf) {
  std::shared_ptr<AVFrame> frame(f, [](AVFrame* p) { av_frame_free(&p); });

  // アクセラレーターが本当に使われたかは、最初のフレームで分かる。
  if (!hw_verified_) {
    hw_verified_ = true;
    hw_bound_ = f->format == AV_PIX_FMT_D3D11;
    if (hw_requested_ && !hw_bound_) {
      log::warn("d3d11va did not bind for this stream (output {}); decoding in software",
                av_get_pix_fmt_name(static_cast<AVPixelFormat>(f->format)));
    } else if (hw_bound_) {
      log::info("d3d11va bound");
    }
  }

  const int64_t pts = f->pts != AV_NOPTS_VALUE ? f->pts : f->best_effort_timestamp;
  auto it = pts_origin_.find(pts);
  if (it == pts_origin_.end()) {
    log::debug("frame pts={} not in map", pts);
    return false;
  }
  vf.tile = it->second.tile;
  vf.rtp_ts = it->second.rtp_ts;
  pts_origin_.erase(it);
  vf.had_error = f->decode_error_flags != 0 || (f->flags & AV_FRAME_FLAG_CORRUPT);

  if (f->format == AV_PIX_FMT_D3D11) {
    std::shared_ptr<AVFrame> sw(av_frame_alloc(), [](AVFrame* p) { av_frame_free(&p); });
    int rc = av_hwframe_transfer_data(sw.get(), f, 0);
    if (rc < 0) {
      log::warn("d3d11va frame download failed: {}", av_err(rc));
      return false;
    }
    av_frame_copy_props(sw.get(), f);
    frame = std::move(sw);
  }

  AVFrame* s = frame.get();
  vf.width = s->width;
  vf.height = s->height;
  if (s->color_range == AVCOL_RANGE_JPEG || s->format == AV_PIX_FMT_YUVJ420P || s->format == AV_PIX_FMT_YUVJ444P) {
    vf.range = VideoFrame::Range::Full;
  } else if (s->color_range == AVCOL_RANGE_MPEG) {
    vf.range = VideoFrame::Range::Limited;
  }
  switch (s->format) {
    case AV_PIX_FMT_YUV420P:
    case AV_PIX_FMT_YUVJ420P:
      vf.layout = VideoFrame::Layout::Planar;
      vf.chroma_width = (s->width + 1) / 2;
      vf.chroma_height = (s->height + 1) / 2;
      vf.av = std::move(frame);
      return true;
    case AV_PIX_FMT_YUV444P:
    case AV_PIX_FMT_YUVJ444P:
      vf.layout = VideoFrame::Layout::Planar;
      vf.chroma_width = s->width;
      vf.chroma_height = s->height;
      vf.av = std::move(frame);
      return true;
    case AV_PIX_FMT_NV12:
      vf.layout = VideoFrame::Layout::Biplanar;
      vf.chroma_width = (s->width + 1) / 2;
      vf.chroma_height = (s->height + 1) / 2;
      vf.av = std::move(frame);
      return true;
    case AV_PIX_FMT_VUYX:  // QSVの4:4:4。そのままアップロードし、シェーダーでほどく
      vf.layout = VideoFrame::Layout::Packed;
      vf.chroma_width = s->width;
      vf.chroma_height = s->height;
      vf.av = std::move(frame);
      return true;
    default:
      break;
  }

  // それ以外（ハードウェアの4:4:4デコードが出すVUYX/AYUVなどのpacked 4:4:4、
  // 10ビットの形式など）→ クロマを間引かないplanar 4:4:4に変換する。
  sws_ = sws_getCachedContext(sws_, s->width, s->height, static_cast<AVPixelFormat>(s->format), s->width,
                              s->height, AV_PIX_FMT_YUV444P, SWS_POINT, nullptr, nullptr, nullptr);
  if (!sws_) {
    log::warn("unsupported decoded format {}", av_get_pix_fmt_name(static_cast<AVPixelFormat>(s->format)));
    return false;
  }
  std::shared_ptr<AVFrame> planar(av_frame_alloc(), [](AVFrame* p) { av_frame_free(&p); });
  planar->format = AV_PIX_FMT_YUV444P;
  planar->width = s->width;
  planar->height = s->height;
  if (av_frame_get_buffer(planar.get(), 0) < 0) return false;
  sws_scale(sws_, s->data, s->linesize, 0, s->height, planar->data, planar->linesize);
  av_frame_copy_props(planar.get(), s);
  vf.layout = VideoFrame::Layout::Planar;
  vf.chroma_width = s->width;
  vf.chroma_height = s->height;
  vf.av = std::move(planar);
  return true;
}

std::vector<Bytes> split_annexb(const Bytes& s) {
  std::vector<Bytes> out;
  const size_t n = s.size();
  size_t i = 0, start = SIZE_MAX;
  while (i + 2 < n) {
    if (s[i] == 0 && s[i + 1] == 0 && s[i + 2] == 1) {
      if (start != SIZE_MAX) {
        size_t end = i;
        while (end > start && s[end - 1] == 0) --end;  // 末尾の0は4バイトのスタートコードの一部
        out.emplace_back(s.begin() + start, s.begin() + end);
      }
      i += 3;
      start = i;
    } else {
      ++i;
    }
  }
  if (start != SIZE_MAX && start < n) out.emplace_back(s.begin() + start, s.end());
  return out;
}

}  // namespace iss::media
