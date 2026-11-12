// D3D11のレンダラー。選んだDXGIアダプタ上のデバイス、フリップモデルのスワップチェーン、
// そして（今のところ）シェーダーのパイプラインが動くことを確かめるテストパターンを持つ。
// フェーズ2でこのパターンをデコードしたYUVテクスチャに置き換える。
#pragma once

#include <windows.h>
#include <d3d11.h>
#include <dxgi1_6.h>
#include <wrl/client.h>

#include <stdexcept>
#include <string>
#include <vector>

#include "media/video_decoder.h"

namespace iss::app {

struct GpuInfo {
  UINT index;  // DXGIアダプタのインデックス。d3d11vaにデバイスとして渡す値でもある
  std::wstring name;
  size_t vram_mb;
  bool software;
};

std::vector<GpuInfo> enumerate_gpus();

class GpuSelectionError : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

// Python版の--gpuと同じ決まり。インデックスか、名前の一部（大文字小文字を
// 区別しない）で指定する。空なら-1を返す（レンダラーが高パフォーマンスGPUを優先する）。
// どれにも合わなければ、アダプタの一覧を載せたGpuSelectionErrorを投げる。
int pick_gpu(const std::vector<GpuInfo>& gpus, const std::wstring& spec);
std::wstring describe_gpus(const std::vector<GpuInfo>& gpus);

class Renderer {
 public:
  // adapter_index < 0 → DXGIの高パフォーマンス優先に任せる。
  void init(HWND hwnd, int adapter_index);
  void resize(UINT width, UINT height);
  // タイルを1枚でもアップロードしたあとは映像のキャンバスを、それまでは
  // テストパターンを描く。内容の縦横比を保つようレターボックスを付ける。
  void render(float time_s);
  const std::wstring& adapter_name() const { return adapter_name_; }

  // 映像キャンバス全体の大きさ（すべてのタイルを縦に積んだもの）。
  void set_canvas(int width, int height);
  // デコードしたタイル1枚を、キャンバスのテクスチャの行
  // [tile_index * slot_height, ...) に書く。キャンバスの高さで切り詰める
  // （Appleのビューアと同じく、最後のタイルのCTUの埋め草の行は捨てる）。
  void upload_tile(int tile_index, const media::VideoFrame& frame, int slot_height);
  // 標準モード。画面を32ビットBGRAのキャンバス（`width` x `height`、行優先）
  // として受け取り、領域(x, y, w, h)をアップロードする。キャンバスの大きさが
  // 変わったらテクスチャを作り直して全体をアップロードする。
  void upload_rgb(const uint32_t* pixels, int width, int height, int x, int y, int w, int h);
  bool has_video() const { return video_ready_; }
  // 映像に重ねるお知らせ。映像を暗くし、中央の枠に `text` と動くバーを出す。
  // これで、これから切り替わる映像が固まったように見えない。
  // `scale` はモニターのDPI / 96。テキストが空なら何も出さない。
  void set_overlay(const std::wstring& text, float scale);
  // ウィンドウのクライアント座標のピクセル → レターボックス付きビューポート
  // を通したキャンバスのピクセル。映像をまだ描いていなければfalse。
  bool window_to_canvas(int wx, int wy, int& cx, int& cy) const;
  // 今のレターボックス付きの表示で、キャンバス1ピクセルあたりのウィンドウの
  // ピクセル数。映像をまだ描いていなければ0。
  float display_scale() const { return video_ready_ && content_w_ > 0 ? vp_w_ / content_w_ : 0.0f; }
  // 最後に表示したバックバッファを32ビットBMPに書き出す（診断用）。
  bool save_bmp(const std::wstring& path);

 private:
  void create_targets();
  void ensure_textures(const media::VideoFrame& first);
  void draw_video();
  void set_yuv_constants();
  void draw_pattern(float time_s);
  void draw_overlay(float time_s);

  template <class T>
  using ComPtr = Microsoft::WRL::ComPtr<T>;
  ComPtr<IDXGIFactory6> factory_;
  ComPtr<ID3D11Device> device_;
  ComPtr<ID3D11DeviceContext> ctx_;
  ComPtr<IDXGISwapChain1> swap_;
  ComPtr<ID3D11RenderTargetView> rtv_;
  ComPtr<ID3D11VertexShader> vs_;
  ComPtr<ID3D11PixelShader> ps_;
  ComPtr<ID3D11PixelShader> ps_yuv_;
  ComPtr<ID3D11Buffer> cbuf_;
  ComPtr<ID3D11Buffer> yuv_cbuf_;
  ComPtr<ID3D11SamplerState> sampler_;
  UINT width_ = 0, height_ = 0;
  std::wstring adapter_name_;

  // 映像キャンバス。Y平面に加え、U/V（planar）かインターリーブしたUV（biplanar）。
  ComPtr<ID3D11Texture2D> tex_[3];
  ComPtr<ID3D11ShaderResourceView> srv_[3];
  int canvas_w_ = 0, canvas_h_ = 0;
  int tex_chroma_w_ = 0, tex_chroma_h_ = 0;
  bool biplanar_ = false;
  bool packed_ = false;  // VUYXのテクスチャ1枚（QSVの4:4:4）
  bool textures_ok_ = false;
  // 標準モードのキャンバス。
  ComPtr<ID3D11PixelShader> ps_rgb_;
  ComPtr<ID3D11Texture2D> rgb_tex_;
  ComPtr<ID3D11ShaderResourceView> rgb_srv_;
  int rgb_w_ = 0, rgb_h_ = 0;
  bool rgb_mode_ = false;
  bool video_ready_ = false;
  bool full_range_ = true;
  int content_w_ = 0, content_h_ = 0;  // タイルで実際に書いた範囲
  float vp_x_ = 0, vp_y_ = 0, vp_w_ = 0, vp_h_ = 0;  // 直近のレターボックス付きビューポート

  // set_overlayの枠（乗算済みアルファのBGRA）と、その中のバーの行（テクスチャのv座標）。
  ComPtr<ID3D11PixelShader> ps_dim_, ps_label_;
  ComPtr<ID3D11BlendState> premultiplied_;
  ComPtr<ID3D11Buffer> overlay_cbuf_;
  ComPtr<ID3D11ShaderResourceView> label_srv_;
  std::wstring overlay_text_;
  float overlay_scale_ = 0;
  int label_w_ = 0, label_h_ = 0;
  float bar_top_ = 0, bar_bottom_ = 0, bar_inset_ = 0;
};

}  // namespace iss::app
