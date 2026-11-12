#include "app/renderer.h"

#include <d3dcompiler.h>

#include <algorithm>
#include <cmath>
#include <cstring>
#include <cwctype>
#include <format>

#include "core/log.h"

namespace iss::app {
namespace {

using Microsoft::WRL::ComPtr;

void check(HRESULT hr, const char* what) {
  if (FAILED(hr)) throw std::runtime_error(std::format("{} failed (hr=0x{:08x})", what, static_cast<uint32_t>(hr)));
}

std::string narrow(const std::wstring& w) {
  if (w.empty()) return {};
  int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
  std::string s(n, '\0');
  WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), s.data(), n, nullptr, nullptr);
  return s;
}

std::wstring lower(std::wstring s) {
  std::transform(s.begin(), s.end(), s.begin(), [](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); });
  return s;
}

// 画面全体を覆う三角形とテストパターン。カラーバー、グレーのグラデーション、
// 1秒に1回横切るバーを描き、Presentのループが止まればすぐ分かるようにする。
constexpr char kShader[] = R"(
cbuffer Frame : register(b0) { float time; float aspect; float2 pad; };
struct VSOut { float4 pos : SV_Position; float2 uv : TEXCOORD0; };

VSOut vs_main(uint id : SV_VertexID) {
  VSOut o;
  float2 uv = float2((id << 1) & 2, id & 2);
  o.pos = float4(uv * float2(2, -2) + float2(-1, 1), 0, 1);
  o.uv = uv;
  return o;
}

float4 ps_main(VSOut i) : SV_Target {
  static const float3 bars[7] = {
    float3(0.75, 0.75, 0.75), float3(0.75, 0.75, 0.0), float3(0.0, 0.75, 0.75),
    float3(0.0, 0.75, 0.0),   float3(0.75, 0.0, 0.75), float3(0.75, 0.0, 0.0),
    float3(0.0, 0.0, 0.75) };
  float3 c;
  if (i.uv.y < 0.66) c = bars[min(6, (int)(i.uv.x * 7.0))];
  else c = i.uv.xxx;
  float sweep = frac(time);
  if (abs(i.uv.x - sweep) < 0.004) c = float3(1, 1, 1);
  return float4(c, 1);
}
)";

// BT.709の行列でYUV → RGB（Python版レンダラーのWGSLと同じ）。ビットストリームが
// limitedと示さない限りfull rangeとして扱う。Appleのストリームはfull rangeだ。
// uv_scaleでサンプリングをタイルが実際に書いた範囲に絞る。色差のテクスチャは
// 同じキャンバスを色差のサブサンプリング比で覆う。
constexpr char kYuvShader[] = R"(
cbuffer Yuv : register(b0) {
  float2 uv_scale; float2 uv_offset;
  float2 chroma_scale; float2 chroma_offset;
  uint biplanar; uint full_range; uint packed; float pad;
};
// Y (R8), or with `packed` the whole picture (VUYX as R8G8B8A8: r = V, g = U, b = Y).
Texture2D<float4> y_tex : register(t0);
Texture2D<float4> c_tex : register(t1);  // U (R8) when planar, UV (R8G8) when biplanar
Texture2D<float> v_tex : register(t2);
SamplerState samp : register(s0);
struct VSOut { float4 pos : SV_Position; float2 uv : TEXCOORD0; };

float4 ps_yuv(VSOut i) : SV_Target {
  float2 luv = i.uv * uv_scale + uv_offset;
  float2 cuv = i.uv * chroma_scale + chroma_offset;
  float4 y4 = y_tex.Sample(samp, luv);
  float y;
  float2 c;
  if (packed) {
    y = y4.b;
    c = y4.gr;
  } else {
    y = y4.r;
    float4 c1 = c_tex.Sample(samp, cuv);
    c = biplanar ? c1.xy : float2(c1.x, v_tex.Sample(samp, cuv));
  }
  float cb = c.x - 0.5, cr = c.y - 0.5;
  if (!full_range) {
    y = (y - 16.0 / 255.0) * (255.0 / 219.0);
    cb *= 255.0 / 224.0;
    cr *= 255.0 / 224.0;
  }
  float3 rgb = float3(y + 1.5748 * cr, y - 0.187324 * cb - 0.468124 * cr, y + 1.8556 * cb);
  return float4(saturate(rgb), 1);
}
)";

// 標準モード。BGRAのキャンバスをそのまま描く。
constexpr char kRgbShader[] = R"(
Texture2D<float4> rgb_tex : register(t0);
SamplerState samp : register(s0);
struct VSOut { float4 pos : SV_Position; float2 uv : TEXCOORD0; };

float4 ps_rgb(VSOut i) : SV_Target { return float4(rgb_tex.Sample(samp, i.uv).rgb, 1); }
)";

// set_overlay用。映像を暗くする処理（乗算済みアルファの黒）と、枠とバーを描く。
// バーは1.25秒に1回、左から右へ走る線分だ。
constexpr char kOverlayShader[] = R"(
cbuffer Overlay : register(b0) { float time; float bar_top; float bar_bottom; float bar_inset; };
Texture2D<float4> label_tex : register(t0);
SamplerState samp : register(s0);
struct VSOut { float4 pos : SV_Position; float2 uv : TEXCOORD0; };

float4 ps_dim(VSOut i) : SV_Target { return float4(0, 0, 0, 0.45); }

float4 ps_label(VSOut i) : SV_Target {
  float4 c = label_tex.Sample(samp, i.uv);
  if (i.uv.y >= bar_top && i.uv.y < bar_bottom && i.uv.x >= bar_inset && i.uv.x < 1 - bar_inset) {
    float x = (i.uv.x - bar_inset) / (1 - 2 * bar_inset);
    float head = frac(time * 0.8) * 1.5 - 0.25;
    float a = abs(x - head) < 0.25 ? 0.9 : 0.25;
    c = float4(a, a, a, a) + c * (1 - a);
  }
  return c;
}
)";

ComPtr<ID3DBlob> compile(const char* src, size_t len, const char* entry, const char* target) {
  ComPtr<ID3DBlob> code, errors;
  HRESULT hr = D3DCompile(src, len, entry, nullptr, nullptr, entry, target,
                          D3DCOMPILE_OPTIMIZATION_LEVEL3, 0, &code, &errors);
  if (FAILED(hr)) {
    std::string msg = errors ? static_cast<const char*>(errors->GetBufferPointer()) : "unknown error";
    throw std::runtime_error("shader compile failed: " + msg);
  }
  return code;
}

}  // namespace

std::vector<GpuInfo> enumerate_gpus() {
  ComPtr<IDXGIFactory1> factory;
  check(CreateDXGIFactory1(IID_PPV_ARGS(&factory)), "CreateDXGIFactory1");
  std::vector<GpuInfo> out;
  ComPtr<IDXGIAdapter1> adapter;
  for (UINT i = 0; factory->EnumAdapters1(i, &adapter) != DXGI_ERROR_NOT_FOUND; ++i) {
    DXGI_ADAPTER_DESC1 d;
    adapter->GetDesc1(&d);
    out.push_back({i, d.Description, d.DedicatedVideoMemory / (1024 * 1024),
                   (d.Flags & DXGI_ADAPTER_FLAG_SOFTWARE) != 0});
    adapter.Reset();
  }
  return out;
}

std::wstring describe_gpus(const std::vector<GpuInfo>& gpus) {
  std::wstring s;
  for (const auto& g : gpus) {
    s += std::format(L"  [{}] {}  ({} MB{})\n", g.index, g.name, g.vram_mb, g.software ? L", software" : L"");
  }
  return s.empty() ? L"  (no adapters found)\n" : s;
}

int pick_gpu(const std::vector<GpuInfo>& gpus, const std::wstring& spec_in) {
  std::wstring spec = spec_in;
  spec.erase(0, spec.find_first_not_of(L" \t"));
  spec.erase(spec.find_last_not_of(L" \t") + 1);
  if (spec.empty()) return -1;
  if (std::all_of(spec.begin(), spec.end(), [](wchar_t c) { return c >= L'0' && c <= L'9'; })) {
    size_t idx = std::stoul(spec);
    if (idx < gpus.size()) return static_cast<int>(idx);
    throw GpuSelectionError(narrow(std::format(L"--gpu {}: index out of range ({} adapter(s)):\n{}", spec,
                                               gpus.size(), describe_gpus(gpus))));
  }
  std::wstring needle = lower(spec);
  for (const auto& g : gpus) {
    if (lower(g.name).find(needle) != std::wstring::npos) return static_cast<int>(g.index);
  }
  throw GpuSelectionError(
      narrow(std::format(L"--gpu {}: no adapter name contains it:\n{}", spec, describe_gpus(gpus))));
}

void Renderer::init(HWND hwnd, int adapter_index) {
  check(CreateDXGIFactory2(0, IID_PPV_ARGS(&factory_)), "CreateDXGIFactory2");

  ComPtr<IDXGIAdapter1> adapter;
  if (adapter_index >= 0) {
    check(factory_->EnumAdapters1(static_cast<UINT>(adapter_index), &adapter), "EnumAdapters1");
  } else {
    check(factory_->EnumAdapterByGpuPreference(0, DXGI_GPU_PREFERENCE_HIGH_PERFORMANCE, IID_PPV_ARGS(&adapter)),
          "EnumAdapterByGpuPreference");
  }
  DXGI_ADAPTER_DESC1 desc;
  adapter->GetDesc1(&desc);
  adapter_name_ = desc.Description;

  UINT flags = D3D11_CREATE_DEVICE_BGRA_SUPPORT | D3D11_CREATE_DEVICE_VIDEO_SUPPORT;
#ifndef NDEBUG
  flags |= D3D11_CREATE_DEVICE_DEBUG;
#endif
  const D3D_FEATURE_LEVEL levels[] = {D3D_FEATURE_LEVEL_11_1, D3D_FEATURE_LEVEL_11_0};
  HRESULT hr = D3D11CreateDevice(adapter.Get(), D3D_DRIVER_TYPE_UNKNOWN, nullptr, flags, levels,
                                 static_cast<UINT>(std::size(levels)), D3D11_SDK_VERSION, &device_, nullptr, &ctx_);
#ifndef NDEBUG
  if (FAILED(hr)) {  // デバッグレイヤーが入っていない
    flags &= ~D3D11_CREATE_DEVICE_DEBUG;
    hr = D3D11CreateDevice(adapter.Get(), D3D_DRIVER_TYPE_UNKNOWN, nullptr, flags, levels,
                           static_cast<UINT>(std::size(levels)), D3D11_SDK_VERSION, &device_, nullptr, &ctx_);
  }
#endif
  check(hr, "D3D11CreateDevice");

  RECT rc;
  GetClientRect(hwnd, &rc);
  width_ = std::max<UINT>(1, rc.right - rc.left);
  height_ = std::max<UINT>(1, rc.bottom - rc.top);

  DXGI_SWAP_CHAIN_DESC1 sd{};
  sd.Width = width_;
  sd.Height = height_;
  sd.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
  sd.SampleDesc.Count = 1;
  sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
  sd.BufferCount = 2;
  sd.SwapEffect = DXGI_SWAP_EFFECT_FLIP_DISCARD;
  sd.AlphaMode = DXGI_ALPHA_MODE_IGNORE;
  check(factory_->CreateSwapChainForHwnd(device_.Get(), hwnd, &sd, nullptr, nullptr, &swap_),
        "CreateSwapChainForHwnd");
  factory_->MakeWindowAssociation(hwnd, DXGI_MWA_NO_ALT_ENTER);

  auto vs = compile(kShader, sizeof(kShader) - 1, "vs_main", "vs_5_0");
  auto ps = compile(kShader, sizeof(kShader) - 1, "ps_main", "ps_5_0");
  auto ps_yuv = compile(kYuvShader, sizeof(kYuvShader) - 1, "ps_yuv", "ps_5_0");
  check(device_->CreateVertexShader(vs->GetBufferPointer(), vs->GetBufferSize(), nullptr, &vs_), "CreateVertexShader");
  check(device_->CreatePixelShader(ps->GetBufferPointer(), ps->GetBufferSize(), nullptr, &ps_), "CreatePixelShader");
  check(device_->CreatePixelShader(ps_yuv->GetBufferPointer(), ps_yuv->GetBufferSize(), nullptr, &ps_yuv_),
        "CreatePixelShader(yuv)");
  auto ps_rgb = compile(kRgbShader, sizeof(kRgbShader) - 1, "ps_rgb", "ps_5_0");
  check(device_->CreatePixelShader(ps_rgb->GetBufferPointer(), ps_rgb->GetBufferSize(), nullptr, &ps_rgb_),
        "CreatePixelShader(rgb)");
  auto ps_dim = compile(kOverlayShader, sizeof(kOverlayShader) - 1, "ps_dim", "ps_5_0");
  auto ps_label = compile(kOverlayShader, sizeof(kOverlayShader) - 1, "ps_label", "ps_5_0");
  check(device_->CreatePixelShader(ps_dim->GetBufferPointer(), ps_dim->GetBufferSize(), nullptr, &ps_dim_),
        "CreatePixelShader(dim)");
  check(device_->CreatePixelShader(ps_label->GetBufferPointer(), ps_label->GetBufferSize(), nullptr, &ps_label_),
        "CreatePixelShader(label)");
  D3D11_BLEND_DESC blend{};
  auto& rt = blend.RenderTarget[0];
  rt.BlendEnable = TRUE;
  rt.SrcBlend = rt.SrcBlendAlpha = D3D11_BLEND_ONE;
  rt.DestBlend = rt.DestBlendAlpha = D3D11_BLEND_INV_SRC_ALPHA;
  rt.BlendOp = rt.BlendOpAlpha = D3D11_BLEND_OP_ADD;
  rt.RenderTargetWriteMask = D3D11_COLOR_WRITE_ENABLE_ALL;
  check(device_->CreateBlendState(&blend, &premultiplied_), "CreateBlendState");

  D3D11_BUFFER_DESC bd{};
  bd.ByteWidth = 16;
  bd.Usage = D3D11_USAGE_DYNAMIC;
  bd.BindFlags = D3D11_BIND_CONSTANT_BUFFER;
  bd.CPUAccessFlags = D3D11_CPU_ACCESS_WRITE;
  check(device_->CreateBuffer(&bd, nullptr, &cbuf_), "CreateBuffer");
  check(device_->CreateBuffer(&bd, nullptr, &overlay_cbuf_), "CreateBuffer(overlay)");
  bd.ByteWidth = 48;
  check(device_->CreateBuffer(&bd, nullptr, &yuv_cbuf_), "CreateBuffer(yuv)");

  D3D11_SAMPLER_DESC sdesc{};
  sdesc.Filter = D3D11_FILTER_MIN_MAG_MIP_LINEAR;
  sdesc.AddressU = sdesc.AddressV = sdesc.AddressW = D3D11_TEXTURE_ADDRESS_CLAMP;
  sdesc.MaxLOD = D3D11_FLOAT32_MAX;
  check(device_->CreateSamplerState(&sdesc, &sampler_), "CreateSamplerState");

  create_targets();
  log::info("D3D11 device on \"{}\"", narrow(adapter_name_));
}

void Renderer::create_targets() {
  ComPtr<ID3D11Texture2D> back;
  check(swap_->GetBuffer(0, IID_PPV_ARGS(&back)), "GetBuffer");
  check(device_->CreateRenderTargetView(back.Get(), nullptr, &rtv_), "CreateRenderTargetView");
}

void Renderer::resize(UINT width, UINT height) {
  if (!swap_ || width == 0 || height == 0 || (width == width_ && height == height_)) return;
  width_ = width;
  height_ = height;
  ctx_->OMSetRenderTargets(0, nullptr, nullptr);
  rtv_.Reset();
  check(swap_->ResizeBuffers(0, width, height, DXGI_FORMAT_UNKNOWN, 0), "ResizeBuffers");
  create_targets();
}

void Renderer::set_canvas(int width, int height) {
  if (width == canvas_w_ && height == canvas_h_) return;
  canvas_w_ = width;
  canvas_h_ = height;
  textures_ok_ = false;  // 次のアップロードで作り直す
  video_ready_ = false;
  content_w_ = content_h_ = 0;
}

void Renderer::ensure_textures(const media::VideoFrame& f) {
  const bool biplanar = f.layout == media::VideoFrame::Layout::Biplanar;
  const bool packed = f.layout == media::VideoFrame::Layout::Packed;
  // 色差のテクスチャは、フレームのサブサンプリング比でキャンバス全体を覆う。
  const int cw = f.chroma_width == f.width ? canvas_w_ : (canvas_w_ + 1) / 2;
  const int ch = f.chroma_height == f.height ? canvas_h_ : (canvas_h_ + 1) / 2;
  if (textures_ok_ && biplanar == biplanar_ && packed == packed_ && cw == tex_chroma_w_ && ch == tex_chroma_h_) return;

  auto make = [&](int i, int w, int h, DXGI_FORMAT fmt) {
    D3D11_TEXTURE2D_DESC td{};
    td.Width = static_cast<UINT>(w);
    td.Height = static_cast<UINT>(h);
    td.MipLevels = 1;
    td.ArraySize = 1;
    td.Format = fmt;
    td.SampleDesc.Count = 1;
    td.Usage = D3D11_USAGE_DEFAULT;
    td.BindFlags = D3D11_BIND_SHADER_RESOURCE;
    // まだ書いていない行が緑にならないよう、先に黒（Y=0、色差=128）で埋める。
    const size_t bpp = fmt == DXGI_FORMAT_R8G8B8A8_UNORM ? 4 : fmt == DXGI_FORMAT_R8G8_UNORM ? 2 : 1;
    std::vector<uint8_t> init(size_t(w) * h * bpp, i == 0 ? 0 : 128);
    if (bpp == 4) {
      for (size_t p = 0; p < init.size(); p += 4) {
        init[p] = init[p + 1] = 128;  // V, U
        init[p + 3] = 255;
      }
    }
    D3D11_SUBRESOURCE_DATA sd{init.data(), static_cast<UINT>(w * bpp), 0};
    tex_[i].Reset();
    srv_[i].Reset();
    check(device_->CreateTexture2D(&td, &sd, &tex_[i]), "CreateTexture2D(canvas)");
    check(device_->CreateShaderResourceView(tex_[i].Get(), nullptr, &srv_[i]), "CreateShaderResourceView");
  };
  packed_ = packed;
  if (packed) {
    make(0, canvas_w_, canvas_h_, DXGI_FORMAT_R8G8B8A8_UNORM);
    for (int i : {1, 2}) {
      tex_[i].Reset();
      srv_[i].Reset();
    }
    biplanar_ = false;
    tex_chroma_w_ = cw;
    tex_chroma_h_ = ch;
    textures_ok_ = true;
    log::info("video canvas {}x{} (packed 4:4:4)", canvas_w_, canvas_h_);
    return;
  }
  make(0, canvas_w_, canvas_h_, DXGI_FORMAT_R8_UNORM);
  if (biplanar) {
    make(1, cw, ch, DXGI_FORMAT_R8G8_UNORM);
    tex_[2].Reset();
    srv_[2].Reset();
  } else {
    make(1, cw, ch, DXGI_FORMAT_R8_UNORM);
    make(2, cw, ch, DXGI_FORMAT_R8_UNORM);
  }
  biplanar_ = biplanar;
  tex_chroma_w_ = cw;
  tex_chroma_h_ = ch;
  textures_ok_ = true;
  log::info("video canvas {}x{} ({}, chroma {}x{})", canvas_w_, canvas_h_, biplanar ? "NV12" : "planar", cw, ch);
}

void Renderer::upload_tile(int tile_index, const media::VideoFrame& f, int slot_height) {
  if (!device_ || !f.av || canvas_w_ <= 0 || canvas_h_ <= 0) return;
  ensure_textures(f);
  const int origin_y = tile_index * slot_height;
  const int rows = std::min({f.height, slot_height, canvas_h_ - origin_y});
  const int w = std::min(f.width, canvas_w_);
  if (rows <= 0 || w <= 0) return;

  D3D11_BOX box{0, static_cast<UINT>(origin_y), 0, static_cast<UINT>(w), static_cast<UINT>(origin_y + rows), 1};
  ctx_->UpdateSubresource(tex_[0].Get(), 0, &box, f.plane(0), static_cast<UINT>(f.stride(0)), 0);

  // 色差の行数と開始位置はサブサンプリング比に合わせる（packedなら色差はない）。
  if (packed_) {
    content_w_ = std::max(content_w_, w);
    content_h_ = std::max(content_h_, origin_y + rows);
    full_range_ = f.range != media::VideoFrame::Range::Limited;
    video_ready_ = true;
    return;
  }
  const bool sub_y = f.chroma_height != f.height;
  const bool sub_x = f.chroma_width != f.width;
  const int c_origin = sub_y ? origin_y / 2 : origin_y;
  const int c_rows = std::min({f.chroma_height, sub_y ? (rows + 1) / 2 : rows, tex_chroma_h_ - c_origin});
  const int c_w = std::min(sub_x ? (w + 1) / 2 : w, tex_chroma_w_);
  if (c_rows > 0 && c_w > 0) {
    D3D11_BOX cbox{0, static_cast<UINT>(c_origin), 0, static_cast<UINT>(c_w), static_cast<UINT>(c_origin + c_rows), 1};
    ctx_->UpdateSubresource(tex_[1].Get(), 0, &cbox, f.plane(1), static_cast<UINT>(f.stride(1)), 0);
    if (!biplanar_) ctx_->UpdateSubresource(tex_[2].Get(), 0, &cbox, f.plane(2), static_cast<UINT>(f.stride(2)), 0);
  }

  content_w_ = std::max(content_w_, w);
  content_h_ = std::max(content_h_, origin_y + rows);
  full_range_ = f.range != media::VideoFrame::Range::Limited;
  video_ready_ = true;
}

void Renderer::upload_rgb(const uint32_t* pixels, int width, int height, int x, int y, int w, int h) {
  if (!device_ || width <= 0 || height <= 0) return;
  if (!rgb_tex_ || width != rgb_w_ || height != rgb_h_) {
    D3D11_TEXTURE2D_DESC td{};
    td.Width = static_cast<UINT>(width);
    td.Height = static_cast<UINT>(height);
    td.MipLevels = 1;
    td.ArraySize = 1;
    td.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
    td.SampleDesc.Count = 1;
    td.Usage = D3D11_USAGE_DEFAULT;
    td.BindFlags = D3D11_BIND_SHADER_RESOURCE;
    D3D11_SUBRESOURCE_DATA sd{pixels, static_cast<UINT>(width * 4), 0};
    rgb_tex_.Reset();
    rgb_srv_.Reset();
    check(device_->CreateTexture2D(&td, &sd, &rgb_tex_), "CreateTexture2D(rgb canvas)");
    check(device_->CreateShaderResourceView(rgb_tex_.Get(), nullptr, &rgb_srv_), "CreateShaderResourceView(rgb)");
    rgb_w_ = width;
    rgb_h_ = height;
    log::info("screen canvas {}x{} (BGRA)", width, height);
  } else {
    x = std::clamp(x, 0, width);
    y = std::clamp(y, 0, height);
    w = std::min(w, width - x);
    h = std::min(h, height - y);
    if (w <= 0 || h <= 0) return;
    D3D11_BOX box{static_cast<UINT>(x), static_cast<UINT>(y), 0, static_cast<UINT>(x + w), static_cast<UINT>(y + h), 1};
    ctx_->UpdateSubresource(rgb_tex_.Get(), 0, &box, pixels + size_t(y) * width + x, static_cast<UINT>(width * 4), 0);
  }
  rgb_mode_ = true;
  content_w_ = width;
  content_h_ = height;
  video_ready_ = true;
}

void Renderer::render(float time_s) {
  if (!swap_) return;
  if (video_ready_) {
    draw_video();
    draw_overlay(time_s);
  } else {
    draw_pattern(time_s);
  }
  HRESULT hr = swap_->Present(1, 0);
  if (hr == DXGI_ERROR_DEVICE_REMOVED || hr == DXGI_ERROR_DEVICE_RESET) {
    throw std::runtime_error(std::format("D3D11 device lost (reason 0x{:08x})",
                                         static_cast<uint32_t>(device_->GetDeviceRemovedReason())));
  }
}

void Renderer::draw_video() {
  if (!rgb_mode_) set_yuv_constants();
  const float clear[4] = {0, 0, 0, 1};
  ctx_->ClearRenderTargetView(rtv_.Get(), clear);

  // レターボックス。内容の縦横比を保った最大の矩形を中央に置く。
  const float win_aspect = static_cast<float>(width_) / height_;
  const float content_aspect = static_cast<float>(content_w_) / content_h_;
  float vw = static_cast<float>(width_), vh = static_cast<float>(height_);
  if (win_aspect > content_aspect) vw = vh * content_aspect;
  else vh = vw / content_aspect;
  D3D11_VIEWPORT vp{(width_ - vw) / 2, (height_ - vh) / 2, vw, vh, 0, 1};
  vp_x_ = vp.TopLeftX;
  vp_y_ = vp.TopLeftY;
  vp_w_ = vw;
  vp_h_ = vh;
  ctx_->RSSetViewports(1, &vp);
  ctx_->OMSetRenderTargets(1, rtv_.GetAddressOf(), nullptr);
  ctx_->IASetPrimitiveTopology(D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
  ctx_->IASetInputLayout(nullptr);
  ctx_->VSSetShader(vs_.Get(), nullptr, 0);
  if (rgb_mode_) {
    ctx_->PSSetShader(ps_rgb_.Get(), nullptr, 0);
    ctx_->PSSetShaderResources(0, 1, rgb_srv_.GetAddressOf());
  } else {
    ctx_->PSSetShader(ps_yuv_.Get(), nullptr, 0);
    ctx_->PSSetConstantBuffers(0, 1, yuv_cbuf_.GetAddressOf());
    ID3D11ShaderResourceView* views[3] = {srv_[0].Get(), srv_[1].Get(), srv_[2].Get()};
    ctx_->PSSetShaderResources(0, 3, views);
  }
  ctx_->PSSetSamplers(0, 1, sampler_.GetAddressOf());
  ctx_->Draw(3, 0);
}

void Renderer::set_yuv_constants() {
  struct alignas(16) Consts {
    float uv_scale[2], uv_offset[2];
    float chroma_scale[2], chroma_offset[2];
    uint32_t biplanar, full_range, packed;
    float pad;
  } c{};
  // 輝度は書いた範囲だけをサンプリングする。色差もキャンバスに対して同じ割合を、
  // （大きさが奇数かもしれない）色差のテクスチャの座標で表す。
  const float fx = static_cast<float>(content_w_) / canvas_w_;
  const float fy = static_cast<float>(content_h_) / canvas_h_;
  c.uv_scale[0] = fx;
  c.uv_scale[1] = fy;
  const int content_cw = tex_chroma_w_ == canvas_w_ ? content_w_ : (content_w_ + 1) / 2;
  const int content_ch = tex_chroma_h_ == canvas_h_ ? content_h_ : (content_h_ + 1) / 2;
  c.chroma_scale[0] = static_cast<float>(content_cw) / tex_chroma_w_;
  c.chroma_scale[1] = static_cast<float>(content_ch) / tex_chroma_h_;
  c.biplanar = biplanar_ ? 1 : 0;
  c.full_range = full_range_ ? 1 : 0;
  c.packed = packed_ ? 1 : 0;
  D3D11_MAPPED_SUBRESOURCE m;
  if (SUCCEEDED(ctx_->Map(yuv_cbuf_.Get(), 0, D3D11_MAP_WRITE_DISCARD, 0, &m))) {
    std::memcpy(m.pData, &c, sizeof(c));
    ctx_->Unmap(yuv_cbuf_.Get(), 0);
  }
}

bool Renderer::window_to_canvas(int wx, int wy, int& cx, int& cy) const {
  if (!video_ready_ || vp_w_ <= 0 || vp_h_ <= 0) return false;
  const float u = std::clamp((wx - vp_x_) / vp_w_, 0.0f, 1.0f);
  const float v = std::clamp((wy - vp_y_) / vp_h_, 0.0f, 1.0f);
  cx = std::min(content_w_ - 1, static_cast<int>(u * content_w_));
  cy = std::min(content_h_ - 1, static_cast<int>(v * content_h_));
  return true;
}

bool Renderer::save_bmp(const std::wstring& path) {
  if (!swap_) return false;
  ComPtr<ID3D11Texture2D> back;
  if (FAILED(swap_->GetBuffer(0, IID_PPV_ARGS(&back)))) return false;
  D3D11_TEXTURE2D_DESC td;
  back->GetDesc(&td);
  td.Usage = D3D11_USAGE_STAGING;
  td.BindFlags = 0;
  td.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
  td.MiscFlags = 0;
  ComPtr<ID3D11Texture2D> staging;
  if (FAILED(device_->CreateTexture2D(&td, nullptr, &staging))) return false;
  ctx_->CopyResource(staging.Get(), back.Get());
  D3D11_MAPPED_SUBRESOURCE m;
  if (FAILED(ctx_->Map(staging.Get(), 0, D3D11_MAP_READ, 0, &m))) return false;

  const uint32_t w = td.Width, h = td.Height, row = w * 4;
  BITMAPFILEHEADER fh{};
  BITMAPINFOHEADER ih{};
  fh.bfType = 0x4D42;  // "BM"
  fh.bfOffBits = sizeof(fh) + sizeof(ih);
  fh.bfSize = fh.bfOffBits + row * h;
  ih.biSize = sizeof(ih);
  ih.biWidth = static_cast<LONG>(w);
  ih.biHeight = -static_cast<LONG>(h);  // 上から下へ
  ih.biPlanes = 1;
  ih.biBitCount = 32;
  ih.biCompression = BI_RGB;
  FILE* f = nullptr;
  bool ok = _wfopen_s(&f, path.c_str(), L"wb") == 0 && f;
  if (ok) {
    fwrite(&fh, sizeof(fh), 1, f);
    fwrite(&ih, sizeof(ih), 1, f);
    for (uint32_t y = 0; y < h; ++y) fwrite(static_cast<uint8_t*>(m.pData) + size_t(y) * m.RowPitch, 1, row, f);
    fclose(f);
  }
  ctx_->Unmap(staging.Get(), 0);
  return ok;
}

void Renderer::set_overlay(const std::wstring& text, float scale) {
  if (text == overlay_text_ && (text.empty() || scale == overlay_scale_)) return;
  overlay_text_ = text;
  overlay_scale_ = scale;
  label_srv_.Reset();
  if (text.empty() || !device_) return;

  // GDIのグレースケールのアンチエイリアスで、黒地に白で文字を描く。ピクセルの
  // 明るさが、そのピクセルを字形が覆う割合になる。
  const auto px = [&](float dips) { return std::max(1, static_cast<int>(std::lround(dips * scale))); };
  HDC dc = CreateCompatibleDC(nullptr);
  HFONT font = CreateFontW(-px(16), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                           CLIP_DEFAULT_PRECIS, ANTIALIASED_QUALITY, DEFAULT_PITCH, L"Yu Gothic UI");
  HGDIOBJ old_font = SelectObject(dc, font);
  SIZE ext{};
  GetTextExtentPoint32W(dc, text.c_str(), static_cast<int>(text.size()), &ext);
  const int pad_x = px(28), pad_y = px(18), gap = px(14), bar_h = px(4);
  const int w = ext.cx + 2 * pad_x, h = pad_y + ext.cy + gap + bar_h + pad_y;
  BITMAPINFO bi{};
  bi.bmiHeader = {sizeof(BITMAPINFOHEADER), w, -h, 1, 32, BI_RGB};
  void* bits = nullptr;
  HBITMAP bmp = CreateDIBSection(dc, &bi, DIB_RGB_COLORS, &bits, nullptr, 0);
  if (bmp) {
    HGDIOBJ old_bmp = SelectObject(dc, bmp);
    std::memset(bits, 0, size_t(w) * h * 4);
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, RGB(255, 255, 255));
    TextOutW(dc, pad_x, pad_y, text.c_str(), static_cast<int>(text.size()));
    GdiFlush();
    // 白い文字の下に80%の黒の角丸の枠を敷く（乗算済みアルファ）。
    const float radius = static_cast<float>(px(10));
    auto* p = static_cast<uint8_t*>(bits);
    for (int y = 0; y < h; ++y) {
      for (int x = 0; x < w; ++x) {
        const float dx = std::max({radius - (x + 0.5f), (x + 0.5f) - (w - radius), 0.0f});
        const float dy = std::max({radius - (y + 0.5f), (y + 0.5f) - (h - radius), 0.0f});
        const float box = std::clamp(radius - std::sqrt(dx * dx + dy * dy) + 0.5f, 0.0f, 1.0f);
        uint8_t* d = p + (size_t(y) * w + x) * 4;
        const float cover = std::max({d[0], d[1], d[2]}) / 255.0f;
        const float a = 0.8f * box + cover * (1 - 0.8f * box);
        const auto v = static_cast<uint8_t>(std::lround(cover * 255));
        d[0] = d[1] = d[2] = v;
        d[3] = static_cast<uint8_t>(std::lround(a * 255));
      }
    }
    D3D11_TEXTURE2D_DESC td{};
    td.Width = static_cast<UINT>(w);
    td.Height = static_cast<UINT>(h);
    td.MipLevels = 1;
    td.ArraySize = 1;
    td.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
    td.SampleDesc.Count = 1;
    td.Usage = D3D11_USAGE_IMMUTABLE;
    td.BindFlags = D3D11_BIND_SHADER_RESOURCE;
    D3D11_SUBRESOURCE_DATA sd{bits, static_cast<UINT>(w * 4), 0};
    ComPtr<ID3D11Texture2D> tex;
    if (SUCCEEDED(device_->CreateTexture2D(&td, &sd, &tex)) &&
        SUCCEEDED(device_->CreateShaderResourceView(tex.Get(), nullptr, &label_srv_))) {
      label_w_ = w;
      label_h_ = h;
      bar_top_ = static_cast<float>(pad_y + ext.cy + gap) / h;
      bar_bottom_ = static_cast<float>(pad_y + ext.cy + gap + bar_h) / h;
      bar_inset_ = static_cast<float>(pad_x) / w;
    }
    SelectObject(dc, old_bmp);
    DeleteObject(bmp);
  }
  SelectObject(dc, old_font);
  DeleteObject(font);
  DeleteDC(dc);
}

void Renderer::draw_overlay(float time_s) {
  if (!label_srv_) return;
  const float factor[4] = {};
  ctx_->OMSetBlendState(premultiplied_.Get(), factor, 0xffffffff);
  D3D11_VIEWPORT whole{0, 0, static_cast<float>(width_), static_cast<float>(height_), 0, 1};
  ctx_->RSSetViewports(1, &whole);
  ctx_->PSSetShader(ps_dim_.Get(), nullptr, 0);
  ctx_->Draw(3, 0);

  D3D11_MAPPED_SUBRESOURCE m;
  if (SUCCEEDED(ctx_->Map(overlay_cbuf_.Get(), 0, D3D11_MAP_WRITE_DISCARD, 0, &m))) {
    const float c[4] = {time_s, bar_top_, bar_bottom_, bar_inset_};
    std::memcpy(m.pData, c, sizeof(c));
    ctx_->Unmap(overlay_cbuf_.Get(), 0);
  }
  // 整数ピクセルに合わせ、テクスチャを1:1で写して文字をくっきりさせる。
  D3D11_VIEWPORT box{std::floor((static_cast<float>(width_) - label_w_) / 2),
                     std::floor((static_cast<float>(height_) - label_h_) / 2), static_cast<float>(label_w_),
                     static_cast<float>(label_h_), 0, 1};
  ctx_->RSSetViewports(1, &box);
  ctx_->PSSetShader(ps_label_.Get(), nullptr, 0);
  ctx_->PSSetConstantBuffers(0, 1, overlay_cbuf_.GetAddressOf());
  ctx_->PSSetShaderResources(0, 1, label_srv_.GetAddressOf());
  ctx_->PSSetSamplers(0, 1, sampler_.GetAddressOf());
  ctx_->Draw(3, 0);
  ctx_->OMSetBlendState(nullptr, factor, 0xffffffff);
}

void Renderer::draw_pattern(float time_s) {
  D3D11_MAPPED_SUBRESOURCE m;
  if (SUCCEEDED(ctx_->Map(cbuf_.Get(), 0, D3D11_MAP_WRITE_DISCARD, 0, &m))) {
    float* f = static_cast<float*>(m.pData);
    f[0] = time_s;
    f[1] = static_cast<float>(width_) / static_cast<float>(height_);
    ctx_->Unmap(cbuf_.Get(), 0);
  }
  const float clear[4] = {0, 0, 0, 1};
  ctx_->ClearRenderTargetView(rtv_.Get(), clear);
  D3D11_VIEWPORT vp{0, 0, static_cast<float>(width_), static_cast<float>(height_), 0, 1};
  ctx_->RSSetViewports(1, &vp);
  ctx_->OMSetRenderTargets(1, rtv_.GetAddressOf(), nullptr);
  ctx_->IASetPrimitiveTopology(D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
  ctx_->IASetInputLayout(nullptr);
  ctx_->VSSetShader(vs_.Get(), nullptr, 0);
  ctx_->PSSetShader(ps_.Get(), nullptr, 0);
  ctx_->PSSetConstantBuffers(0, 1, cbuf_.GetAddressOf());
  ctx_->Draw(3, 0);
}

}  // namespace iss::app
