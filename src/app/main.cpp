// iss-winのエントリポイント。接続ダイアログ → ビューアウィンドウ（ステータスバー +
// D3D11の描画ビュー）でMacの画面を映し、ビュー内のキーボードとマウスはMacへ送る。
// 仮想ディスプレイが2枚（高パフォーマンス）のときは、2枚目に専用のウィンドウを開く。
// Ctrl+Alt+Enter（またはウィンドウメニュー）で全画面を切り替え、各ウィンドウが
// それぞれ別のモニターを覆う。
//
//   iss-win.exe [--host H] [--port P] [--user U] [--gpu INDEX|NAME] [--list-gpus]
//               [--connect]         （ダイアログを出さない。保存した設定と、資格情報
//                                    マネージャーに保存したパスワードを使う）
//               [--password-stdin]  （--connectで、標準入力の1行目をパスワードにする）
//               [--alt-session] [--no-curtain] [--software-decode]
//               [--ipv4 | --ipv6]   （高パフォーマンス。ホストのそのアドレスファミリーだけを
//                                    使う。既定は名前にIPv4があればIPv4、なければIPv6）
//               [--displays 1|2]    （Macの仮想ディスプレイの数で、1枚に1ウィンドウ。
//                                    高パフォーマンスかつカーテンありのとき。既定はダイアログの選択）
//               [--fullscreen]      （Ctrl+Alt+Enterと同じく全画面で始める）
//               [--input-test]      （接続後、表示するフレームごとにMacのポインタを円を描くように
//                                    動かす。--legacy-cursorと併用するとMacの画面が変わり
//                                    続けるので、フレームレートの確認に使える）
//               [--perf]            （5秒ごとにフレームのタイミングをログに出す。Macが送る量、
//                                    デコード、アップロード、画面に出るまでの遅延）
//               [--standard]        （画面共有の標準モード。画面をTCPのフレームバッファ更新で
//                                    受け、UDPのメディアは使わない）
//               [--quality adaptive|bw|gray|thousands|millions]  （標準モード。既定はthousands。
//                                    接続中も画質メニューから切り替えられる）
//               [--encodings LIST]  （標準モードのSetEncodings。例 1002,6,16）
//               [--dump-records PATH]  （復号した制御チャネルのレコードをすべて書き出す）
//               [--wake-test]       （ディスプレイがスリープしてMacの映像が2分来なくなったら、
//                                    ポインタを少し動かして起こし、30秒後に終わる。
//                                    ストリームは戻ってこなければならない）
//               [--no-keyboard-grab]  （WinキーをWindowsに残す。既定ではMacのCmdになる）
//               [--key-test]        （再生中は3秒でa、Win+、bを送る。接続中は6秒でWin+Space、
//                                    --smokeの終了時にEscを送る。送ったkeysymをログに出す）
//               [--log]             （ログファイルを書く。既定はオフで、--perf、--log-input、
//                                    --key-test、--smokeのときはオン）
//               [--log-input]       （キーとボタンのタイミングと、送った入力をログに出す）
//               [--view-only]       （このPCのキーボードとマウスの入力を送らない。自動実行
//                                    向け。テスト入力は送る）
//               [--legacy-cursor]   （Macがカーソルを映像に描き込む）
//               [--advertise WxH[@SCALE]]  （固定の仮想ディスプレイ。例 1920x1080@2。
//                                    既定はウィンドウに合わせ、リサイズにも追従する）
//               [--hevc-probe WxH@SCALE]  （実験用。上限の3840x2160を超えるそのサイズの
//                                    ディスプレイを1枚にしてHEVCを提示する。接続はストリーム
//                                    のSPSにあるサイズを出して失敗する。何も表示しない）
//               [--hevc [WxH@SCALE]]  （映像をHEVC 4:4:4にしてIntel Quick Syncでデコード
//                                    するので、Macのディスプレイを7680x4320まで上げられる。
//                                    IntelのGPUが必要で、描画はいつもどおり--gpuのGPUで行う。
//                                    自動解像度と2枚のディスプレイはH.264と同じ。サイズを
//                                    指定するとそのサイズで固定する。例 2560x1440@2）
//               [--hevc420 [WxH@SCALE]]  （同じことをHEVC 4:2:0で行い、--gpuのGPUのD3D11VA
//                                    でデコードする。HEVC 4:4:4のないAMDでも動く）
//               [--h264]            （ダイアログのコーデックに関係なくH.264を使う）
//               [--verbose]         （ログにデバッグ行も出す）
//               [--resize-test]     （接続後、3秒でウィンドウを縮め、9秒で元に戻す）
//               [--smoke SECONDS]   （N秒描画し、フレーム数をログに出して終わる。
//                                    --connectのときはセッションが立ち上がってからN秒）
//               [--screenshot PATH.bmp]  （--smokeの終了時に保存する。2枚目のディスプレイの
//                                    ものはPATH-2.bmp）
//               [--play FILE.h265|FILE.h264]
//                                   （ダイアログなし。ローカルのクリップをデコードしてループ表示する）
#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>
#include <shellapi.h>
#include <wtsapi32.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <vector>
#include <format>
#include <memory>
#include <optional>
#include <string>
#include <thread>

#include "app/connect_dialog.h"
#include "app/credentials.h"
#include "app/display_change.h"
#include "app/player.h"
#include "app/renderer.h"
#include "app/screen_layout.h"
#include "app/split_pictures.h"
#include "core/bytes.h"
#include "core/log.h"
#include "input/input_mapper.h"
#include "input/keyboard_grab.h"
#include "session/session.h"

namespace {

using namespace iss;
using namespace iss::app;

constexpr wchar_t kMainClass[] = L"IssWinMain";
constexpr wchar_t kSecondClass[] = L"IssWinSecondDisplay";
constexpr wchar_t kViewClass[] = L"IssWinRenderView";
// （WM_APP + 1はconnect_dialog.hのWM_APP_CONNECT_RESULT）
// ビュー宛て。キーボードのグラブが取ったキーがKeyboardGrab::take()で待っている。
constexpr UINT WM_APP_GRABBED_KEY = WM_APP + 2;
// 画質メニューのコマンド。この値 + mode_choices()の添字。
constexpr UINT kCmdModeBase = 100;
// ウィンドウ（システム）メニューの全画面。下位4ビットはWindows自身が使うので、
// こうしたIDでは0にしておく。
constexpr UINT kSysCmdFullscreen = 0x0010;
// 既存のものに加える終了コード（2 = --gpuが不正、3 = レンダラーなし）。
constexpr int kExitNoCredentials = 4;
constexpr int kExitSessionFailed = 5;
constexpr int kMaxDisplays = 2;  // 高パフォーマンスでは仮想ディスプレイを2枚まで使える

// 画面上のMacのディスプレイ1枚分。トップレベルウィンドウの中の描画ビューで、1枚目は
// メインウィンドウ（ステータスバー、メニュー）に、2枚目の仮想ディスプレイは専用の
// ウィンドウに入る。
struct DisplayView {
  HWND frame = nullptr;  // トップレベルウィンドウ
  HWND view = nullptr;
  Renderer renderer;
  bool render_ok = false;
  bool minimized = false;
  int frame_w = 0, frame_h = 0;  // 最後にアップロードした映像（ポインタの換算用）
  int stream = -1;               // 表示している映像ストリーム（stream_for）。最初の映像までは-1
  // 自動解像度。最後に伝えたビューのサイズ（とDPI）と、ウィンドウが落ち着くのを
  // 待っている新しいサイズ。
  int adv_w = 0, adv_h = 0;
  UINT adv_dpi = 0;
  int pending_w = -1, pending_h = -1;
  UINT pending_dpi = 0;
  std::chrono::steady_clock::time_point pending_since{};
  bool fullscreen = false;
  WINDOWPLACEMENT windowed{};  // 全画面にする前の位置
  // このビュー用のMacのカーソル形状で、そのモニターのWindowsの拡大率に合わせてある。
  // nullなら既定の矢印。
  HCURSOR cursor = nullptr;
  float cursor_scale = 0;
  DisplayChange change;  // Macがこのディスプレイを作り直している間、映像に重ねる表示
  std::chrono::steady_clock::time_point change_done{};  // 最後の変更が終わった時刻
  // 最後に要求したサイズ（ポイント）。Macの答えを確かめるまで持つ。それと、答えが
  // 違ったために要求をやり直した回数。
  int asked_w = 0, asked_h = 0;
  uint64_t asked_layouts = 0;
  int asked_again = 0;
};

struct App {
  HINSTANCE inst = nullptr;
  HWND main = nullptr;  // displays[0].frame
  HWND status = nullptr;
  HMENU menu_bar = nullptr;  // メインウィンドウのもの。標準モードの画質メニュー。全画面では外す
  HMENU quality_bar = nullptr;
  DisplayView displays[kMaxDisplays];
  int n_displays = 1;
  // ボタンを押している間、ポインタが通るディスプレイ（ポインタの下にあるビュー、
  // または最後に上にあったビュー）。
  DisplayView* drag_view = nullptr;
  bool arrange_pending = false;  // 両方のウィンドウが全画面になった。arrange_like_mac()を1回呼ぶ
  std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
  // セッションがないときは、入力イベントをステータスバーに表示するだけ。
  std::wstring last_input;
  std::unique_ptr<input::InputMapper> input;
  input::KeyboardGrab grab;  // Win → MacのCmd
  bool log_keys = false;     // --key-testのときだけ。それ以外ではキー入力をログに出さない
  bool log_input = false;    // --log-input。キーとボタンのタイミング、送ったキーとポインタのイベント
  bool view_only = false;    // --view-only。このPCのキーボードとマウスは手元に残す

  std::shared_ptr<session::Session> session;
  std::atomic<bool> connecting{false};
  bool session_up = false;
  std::wstring host_label;
  int mode = 0;                  // mode_choices()の添字。高パフォーマンスか、標準モードの画質
  HMENU quality_menu = nullptr;  // 標準モードのときだけ
  int exit_code = 0;

  session::CursorRef cursor_shape;  // Macのカーソル（enc 1104）。ビューごとにそのHCURSORを持つ

  bool dynamic_resolution = false;
  std::chrono::steady_clock::time_point last_resize_request{};
  bool hevc = false;  // --hevc / --hevc420。Macのディスプレイは3840x2160を超えてよい
};
App g_app;

DisplayView& primary() { return g_app.displays[0]; }

// `hwnd`がビューかウィンドウであるディスプレイ。どちらでもなければnull。
DisplayView* display_of(HWND hwnd) {
  for (int i = 0; i < g_app.n_displays; ++i) {
    if (hwnd && (g_app.displays[i].view == hwnd || g_app.displays[i].frame == hwnd)) return &g_app.displays[i];
  }
  return nullptr;
}

// 新しいサイズが0.3秒続き、どちらかの軸で32 px変わる（またはDPIの変更を伴う）ことを
// 条件とし、要求は2秒以上空ける。要求のたびにMacは仮想ディスプレイを作り直し（試した
// Macで約1.6秒）、エンコーダーを再起動するため。（Pythonのビューアは0.5秒 / 2.5秒
// 待つ。）
constexpr auto kResizeDebounce = std::chrono::milliseconds(300);
constexpr auto kResizeMinInterval = std::chrono::milliseconds(2000);
constexpr int kResizeMinDeltaPx = 32;
// ディスプレイの変更が終わって（新しい映像が出て）から次の要求までの間隔。それと、
// 違うサイズで答えられたときに続けて要求し直す回数。
constexpr auto kResizeSettle = std::chrono::milliseconds(1000);
constexpr int kAskAgainMax = 2;

double now_ms() {
  return std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now().time_since_epoch()).count();
}

std::string narrow(const std::wstring& w) {
  if (w.empty()) return {};
  int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
  std::string s(n, '\0');
  WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), s.data(), n, nullptr, nullptr);
  return s;
}

std::wstring widen(const std::string& s) {
  if (s.empty()) return {};
  int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
  std::wstring w(n, L'\0');
  MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), w.data(), n);
  return w;
}

void wipe(std::wstring& w) {
  secure_wipe(w.data(), w.size() * sizeof(wchar_t));
  w.clear();
}

void set_status(const std::wstring& text) {
  if (g_app.status) SendMessageW(g_app.status, SB_SETTEXTW, 0, reinterpret_cast<LPARAM>(text.c_str()));
}

// ログファイル（--log）。カレントディレクトリの下のlogs\iss-win.log。別のインスタンスが
// そこに書いている間はiss-win-<pid>.log。%LOCALAPPDATA%はシステムのSSDにあるので
// 使わない。
void open_log_file() {
  wchar_t cwd[MAX_PATH];
  const DWORD n = GetCurrentDirectoryW(MAX_PATH, cwd);
  if (n == 0 || n >= MAX_PATH) return;
  const std::wstring dir = std::wstring(cwd) + L"\\logs";
  CreateDirectoryW(dir.c_str(), nullptr);
  if (!log::set_file(dir + L"\\iss-win.log")) log::set_file(std::format(L"{}\\iss-win-{}.log", dir, GetCurrentProcessId()));
}

// ホストのストレートアルファのBGRA形状から、`scale`倍にリサンプルしたWin32の
// カーソルを作る（縮小時はアルファで重み付けした面積平均）。
HCURSOR make_cursor(const session::CursorShape& s, float scale) {
  const int w = std::max(1, static_cast<int>(std::lround(s.width * scale)));
  const int h = std::max(1, static_cast<int>(std::lround(s.height * scale)));
  std::vector<uint8_t> px(size_t(w) * h * 4, 0);
  for (int y = 0; y < h; ++y) {
    const int sy0 = y * s.height / h, sy1 = std::max(sy0 + 1, (y + 1) * s.height / h);
    for (int x = 0; x < w; ++x) {
      const int sx0 = x * s.width / w, sx1 = std::max(sx0 + 1, (x + 1) * s.width / w);
      uint32_t b = 0, g = 0, r = 0, a = 0, n = 0;
      for (int sy = sy0; sy < sy1; ++sy) {
        for (int sx = sx0; sx < sx1; ++sx) {
          const uint8_t* p = &s.bgra[(size_t(sy) * s.width + sx) * 4];
          b += p[0] * p[3];
          g += p[1] * p[3];
          r += p[2] * p[3];
          a += p[3];
          ++n;
        }
      }
      uint8_t* d = &px[(size_t(y) * w + x) * 4];
      if (a) {
        d[0] = static_cast<uint8_t>(b / a);
        d[1] = static_cast<uint8_t>(g / a);
        d[2] = static_cast<uint8_t>(r / a);
      }
      d[3] = static_cast<uint8_t>(a / n);
    }
  }
  BITMAPV5HEADER bi{};
  bi.bV5Size = sizeof(bi);
  bi.bV5Width = w;
  bi.bV5Height = -h;  // トップダウン
  bi.bV5Planes = 1;
  bi.bV5BitCount = 32;
  bi.bV5Compression = BI_BITFIELDS;
  bi.bV5RedMask = 0x00FF0000;
  bi.bV5GreenMask = 0x0000FF00;
  bi.bV5BlueMask = 0x000000FF;
  bi.bV5AlphaMask = 0xFF000000;
  void* bits = nullptr;
  HDC dc = GetDC(nullptr);
  HBITMAP color = CreateDIBSection(dc, reinterpret_cast<BITMAPINFO*>(&bi), DIB_RGB_COLORS, &bits, nullptr, 0);
  ReleaseDC(nullptr, dc);
  if (!color) return nullptr;
  std::memcpy(bits, px.data(), px.size());
  const std::vector<uint8_t> zeros(size_t((w + 15) / 16) * 2 * h, 0);  // マスクは未使用。アルファで決まる
  HBITMAP mask = CreateBitmap(w, h, 1, 1, zeros.data());
  ICONINFO ii{FALSE, static_cast<DWORD>(std::min(w - 1, static_cast<int>(s.hot_x * scale))),
              static_cast<DWORD>(std::min(h - 1, static_cast<int>(s.hot_y * scale))), mask, color};
  HCURSOR c = reinterpret_cast<HCURSOR>(CreateIconIndirect(&ii));
  DeleteObject(color);
  DeleteObject(mask);
  return c;
}

void apply_view_cursor() {
  POINT pt;
  if (!GetCursorPos(&pt)) return;
  const HWND under = WindowFromPoint(pt);
  for (int i = 0; i < g_app.n_displays; ++i) {
    const DisplayView& d = g_app.displays[i];
    if (under == d.view) SetCursor(d.cursor ? d.cursor : LoadCursorW(nullptr, IDC_ARROW));
  }
}

// Macから新しい形状が来たか、ビューが別の拡大率のモニターに移ったら、そのビューの
// カーソルを作り直す。形状はポイント単位で届く。1ポイントをビューのモニターでの
// WindowsのDIP 1つ分（150%なら1.5ピクセル）で描き、そこでのWindowsのカーソルと
// 同じ大きさにする。自動解像度では、Macの上限3840x2160に達しない限り、Macの
// 1ポイントはもともと1 DIPになる。
void update_remote_cursor() {
  bool new_shape = false;
  if (auto c = g_app.session->take_cursor()) {
    g_app.cursor_shape = std::move(*c);
    new_shape = true;
  }
  bool changed = false;
  std::vector<HCURSOR> old;
  for (int i = 0; i < g_app.n_displays; ++i) {
    DisplayView& d = g_app.displays[i];
    const float scale = GetDpiForWindow(d.view) / 96.0f;
    if (!new_shape && std::abs(scale - d.cursor_scale) < 0.01f) continue;
    if (std::abs(scale - d.cursor_scale) >= 0.01f) log::info("window {}: Mac cursor at {}x (monitor scale)", i + 1, scale);
    if (d.cursor) old.push_back(d.cursor);
    d.cursor = g_app.cursor_shape ? make_cursor(*g_app.cursor_shape, scale) : nullptr;
    d.cursor_scale = scale;
    changed = true;
  }
  if (!changed) return;
  apply_view_cursor();  // 古いハンドルを捨てる前に呼ぶ。そのどれかが画面に出ているかもしれない
  for (HCURSOR c : old) DestroyCursor(c);
}

void layout_children() {
  RECT rc;
  GetClientRect(g_app.main, &rc);
  int sb_h = 0;
  // IsWindowVisibleでなくスタイルのビットを見る。メインウィンドウの表示前にも通るため。
  if (GetWindowLongPtrW(g_app.status, GWL_STYLE) & WS_VISIBLE) {
    SendMessageW(g_app.status, WM_SIZE, 0, 0);
    RECT sb;
    GetWindowRect(g_app.status, &sb);
    sb_h = sb.bottom - sb.top;
  }
  MoveWindow(primary().view, 0, 0, rc.right, std::max(1L, rc.bottom - sb_h), TRUE);
}

// グラブしたキーはポストされたメッセージで届き、入力メッセージより先に読まれる。
// 1つを処理する前に、それより前に来た通常のキーメッセージを処理しておく。こうする
// ことで、"a"に続けてWinを押したときにMacへCmd+Aとして届かない。
void dispatch_keys_before(DWORD time) {
  MSG m;
  while (PeekMessageW(&m, nullptr, WM_KEYFIRST, WM_KEYLAST, PM_NOREMOVE)) {
    // 保留中の文字は、既に変換済みのキーから来たもの。
    const bool chr = m.message == WM_CHAR || m.message == WM_DEADCHAR || m.message == WM_SYSCHAR ||
                     m.message == WM_SYSDEADCHAR || m.message == WM_UNICHAR;
    if (!chr && static_cast<LONG>(m.time - time) > 0) break;
    PeekMessageW(&m, nullptr, WM_KEYFIRST, WM_KEYLAST, PM_REMOVE);
    TranslateMessage(&m);
    DispatchMessageW(&m);
  }
}

// ウィンドウ`window`が表示する映像ストリーム。そのディスプレイはレイアウトの
// window番目（要求した順で、それぞれウィンドウに合わせたサイズ）で、ストリームは
// バッキングキャンバスを左から右へ並ぶ。
int stream_for(int window, const std::vector<rfb::DisplayRect>& rects) {
  if (g_app.n_displays < 2 || window >= static_cast<int>(rects.size())) return window;
  const rfb::DisplayRect& mine = rects[window];
  int rank = 0;
  for (const rfb::DisplayRect& r : rects) {
    if (r.x < mine.x || (r.x == mine.x && r.y < mine.y)) ++rank;
  }
  return rank;
}

// ディスプレイ`d`の映像のピクセル → Macのポインタ座標。1枚のときはエンコーダーの
// キャンバス（映像はそれを拡大縮小したものの場合がある）。2枚のときは、両方に
// またがるバッキングキャンバスでのそのディスプレイの矩形。
bool picture_to_host(const DisplayView& d, int x, int y, int& hx, int& hy) {
  if (!g_app.session_up) {
    hx = x;
    hy = y;
    return true;
  }
  const int index = static_cast<int>(&d - g_app.displays);
  if (g_app.n_displays > 1) {
    const std::vector<rfb::DisplayRect> rects = g_app.session->display_rects();
    if (index >= static_cast<int>(rects.size()) || d.frame_w <= 0 || d.frame_h <= 0) return false;
    const rfb::DisplayRect& r = rects[index];
    hx = r.x + x * r.w / d.frame_w;
    hy = r.y + y * r.h / d.frame_h;
    return true;
  }
  const int cw = g_app.session->canvas_width(), ch = g_app.session->canvas_height();
  hx = d.frame_w > 0 && cw > 0 && cw != d.frame_w ? x * cw / d.frame_w : x;
  hy = d.frame_h > 0 && ch > 0 && ch != d.frame_h ? y * ch / d.frame_h : y;
  return true;
}

// スクリーン座標`pt`で最前面のウィンドウが描画ビューになっているディスプレイ。
// ほかのものがあればnull。
DisplayView* view_at(POINT pt) {
  const HWND under = WindowFromPoint(pt);
  for (int i = 0; i < g_app.n_displays; ++i) {
    if (under && g_app.displays[i].view == under) return &g_app.displays[i];
  }
  return nullptr;
}

// 全画面はモニター全体を覆う枠なしのウィンドウで、DXGIの排他モードは使わない。
// もう一方のウィンドウやWindowsのほかの部分も使えるままにするため。
void enter_fullscreen(DisplayView& d, HMONITOR monitor, bool activate) {
  MONITORINFO mi{sizeof(mi)};
  d.windowed.length = sizeof(d.windowed);
  if (!GetMonitorInfoW(monitor, &mi) || !GetWindowPlacement(d.frame, &d.windowed)) return;
  d.fullscreen = true;
  if (d.frame == g_app.main) {
    SetMenu(g_app.main, nullptr);
    ShowWindow(g_app.status, SW_HIDE);
  }
  SetWindowLongPtrW(d.frame, GWL_STYLE, GetWindowLongPtrW(d.frame, GWL_STYLE) & ~WS_OVERLAPPEDWINDOW);
  const RECT& r = mi.rcMonitor;
  // まだ隠れている（接続中の）ウィンドウは、接続ダイアログからアクティブを奪ってはいけない。
  activate = activate && IsWindowVisible(d.frame);
  SetWindowPos(d.frame, HWND_TOP, r.left, r.top, r.right - r.left, r.bottom - r.top,
               SWP_NOOWNERZORDER | SWP_FRAMECHANGED | (activate ? 0 : SWP_NOACTIVATE));
  log::info("full screen: window {} on the monitor at {},{} ({}x{})", &d - g_app.displays + 1, r.left, r.top,
            r.right - r.left, r.bottom - r.top);
}

void leave_fullscreen(DisplayView& d) {
  d.fullscreen = false;
  SetWindowLongPtrW(d.frame, GWL_STYLE, GetWindowLongPtrW(d.frame, GWL_STYLE) | WS_OVERLAPPEDWINDOW);
  if (d.frame == g_app.main) {
    ShowWindow(g_app.status, SW_SHOW);
    SetMenu(g_app.main, g_app.menu_bar);
  }
  WINDOWPLACEMENT wp = d.windowed;
  if (!IsWindowVisible(d.frame)) wp.showCmd = SW_HIDE;  // 保存した表示状態のままだと表示されてしまう
  SetWindowPlacement(d.frame, &wp);
  SetWindowPos(d.frame, nullptr, 0, 0, 0, 0,
               SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOOWNERZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED);
  log::info("full screen: window {} back to a window", &d - g_app.displays + 1);
}

// `from`でCtrl+Alt+Enterかウィンドウメニューを使ったとき。全画面のウィンドウからなら、
// すべてのウィンドウを元の位置に戻す。そうでなければ`from`とほかのウィンドウを全画面に
// し、それぞれ自分のいるモニターに置く。そのモニターをほかのウィンドウが使っていれば
// 空いているモニターに置き、空きがなければそのウィンドウはそのままにする。
void toggle_fullscreen(DisplayView& from) {
  if (from.fullscreen) {
    // `from`は最後に戻す。ウィンドウを元に戻すとアクティブになるため。
    for (int i = 0; i < g_app.n_displays; ++i) {
      if (g_app.displays[i].fullscreen && &g_app.displays[i] != &from) leave_fullscreen(g_app.displays[i]);
    }
    leave_fullscreen(from);
  } else {
    if (IsIconic(from.frame)) ShowWindow(from.frame, SW_RESTORE);
    std::vector<HMONITOR> monitors;
    EnumDisplayMonitors(
        nullptr, nullptr,
        [](HMONITOR m, HDC, LPRECT, LPARAM lp) -> BOOL {
          reinterpret_cast<std::vector<HMONITOR>*>(lp)->push_back(m);
          return TRUE;
        },
        reinterpret_cast<LPARAM>(&monitors));
    auto monitor_of = [&](HWND w) {
      const auto it = std::find(monitors.begin(), monitors.end(), MonitorFromWindow(w, MONITOR_DEFAULTTONEAREST));
      return it == monitors.end() ? -1 : static_cast<int>(it - monitors.begin());
    };
    std::vector<bool> taken(monitors.size(), false);
    std::vector<DisplayView*> going{&from};
    for (int i = 0; i < g_app.n_displays; ++i) {
      DisplayView& d = g_app.displays[i];
      if (d.fullscreen) {
        if (const int m = monitor_of(d.frame); m >= 0) taken[m] = true;
      } else if (&d != &from && !IsIconic(d.frame)) {
        going.push_back(&d);
      }
    }
    std::vector<int> on;
    for (const DisplayView* d : going) on.push_back(monitor_of(d->frame));
    const std::vector<int> target = fullscreen_monitors(on, taken);
    for (size_t i = 0; i < going.size(); ++i) {
      if (target[i] >= 0) enter_fullscreen(*going[i], monitors[target[i]], going[i] == &from);
    }
  }
  g_app.arrange_pending = g_app.n_displays > 1 && g_app.displays[0].fullscreen && g_app.displays[1].fullscreen;
  for (int i = 0; i < g_app.n_displays; ++i) {
    const DisplayView& d = g_app.displays[i];
    CheckMenuItem(GetSystemMenu(d.frame, FALSE), kSysCmdFullscreen,
                  MF_BYCOMMAND | (d.fullscreen ? MF_CHECKED : MF_UNCHECKED));
  }
  if (IsWindowVisible(from.frame)) SetFocus(from.view);
}

// 両方のウィンドウが全画面で、Macのレイアウトが分かっているとき。モニターの左右の
// 並びがMacのディスプレイと逆なら入れ替え、Macでディスプレイが接している所で
// ポインタが行き来するようにする。全画面1回につき1度だけ行う。新しいサイズで
// Macはディスプレイを作り直し、2枚目をまた反対側に置くことがあるため。
void arrange_like_mac(const std::vector<rfb::DisplayRect>& rects) {
  g_app.arrange_pending = false;
  DisplayView& a = g_app.displays[0];
  DisplayView& b = g_app.displays[1];
  if (rects.size() < 2 || !a.fullscreen || !b.fullscreen) return;
  MONITORINFO ma{sizeof(ma)}, mb{sizeof(mb)};
  if (!GetMonitorInfoW(MonitorFromWindow(a.frame, MONITOR_DEFAULTTONEAREST), &ma) ||
      !GetMonitorInfoW(MonitorFromWindow(b.frame, MONITOR_DEFAULTTONEAREST), &mb) ||
      !monitors_against_mac_order(ma.rcMonitor.left, mb.rcMonitor.left, rects[0].x, rects[1].x)) {
    return;
  }
  log::info("full screen: the Mac has display 2 on its {}; swapping the windows' monitors",
            rects[1].x > rects[0].x ? "right" : "left");
  for (auto [d, r] : {std::pair{&a, mb.rcMonitor}, std::pair{&b, ma.rcMonitor}}) {
    SetWindowPos(d->frame, nullptr, r.left, r.top, r.right - r.left, r.bottom - r.top,
                 SWP_NOZORDER | SWP_NOOWNERZORDER | SWP_NOACTIVATE);
  }
}

LRESULT CALLBACK view_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
  auto* in = g_app.input.get();
  DisplayView* d = display_of(hwnd);
  // ボタンを押している間は、押したビューがマウスをキャプチャしている。そのビューの
  // 外では、ポインタの下にあるビューのディスプレイ（どちらの上にもなければ最後の
  // もの）を通してポインタを動かす。こうすることで、Mac上でドラッグしたウィンドウを
  // もう一方のディスプレイへ移せる。
  auto mouse_to_canvas = [&](LPARAM l) {
    if (!in || !d) return;
    DisplayView* target = d;
    POINT pt{GET_X_LPARAM(l), GET_Y_LPARAM(l)};
    if (g_app.n_displays > 1 && GetCapture() == hwnd) {
      POINT screen = pt;
      ClientToScreen(hwnd, &screen);
      if (DisplayView* under = view_at(screen)) g_app.drag_view = under;
      if (g_app.drag_view && g_app.drag_view != d) {
        target = g_app.drag_view;
        pt = screen;
        ScreenToClient(target->view, &pt);
      }
      // キャプチャ中はWM_SETCURSORが来ないので、上にあるビュー用の大きさのカーソルにする。
      if (target->cursor) SetCursor(target->cursor);
    }
    int cx, cy, hx, hy;
    if (target->renderer.window_to_canvas(pt.x, pt.y, cx, cy) && picture_to_host(*target, cx, cy, hx, hy)) {
      in->move(hx, hy);
    }
  };
  // --log-input。キーやボタンのイベントが送られるまでキューに残っていた時間
  // （GetMessageTimeはWindowsがキューに入れた時刻。分解能は約16 ms）。
  if (g_app.log_input) {
    const char* what = nullptr;
    switch (msg) {
      case WM_KEYDOWN: case WM_SYSKEYDOWN: what = "key down"; break;
      case WM_KEYUP: case WM_SYSKEYUP: what = "key up"; break;
      case WM_LBUTTONDOWN: case WM_RBUTTONDOWN: case WM_MBUTTONDOWN: what = "button down"; break;
      case WM_LBUTTONUP: case WM_RBUTTONUP: case WM_MBUTTONUP: what = "button up"; break;
    }
    if (what) {
      log::info("input: {} vk 0x{:02x}, {} ms after Windows queued it", what,
                msg == WM_KEYDOWN || msg == WM_SYSKEYDOWN || msg == WM_KEYUP || msg == WM_SYSKEYUP ? wp : 0,
                static_cast<LONG>(GetTickCount() - static_cast<DWORD>(GetMessageTime())));
    }
  }
  switch (msg) {
    case WM_KEYDOWN:
    case WM_SYSKEYDOWN:
      // Ctrl+Alt+Enterはこちらで処理する（MacにはCtrlとOptionの押下と解放だけが
      // 届く）。オートリピートでは何もしない。
      if (wp == VK_RETURN && GetKeyState(VK_CONTROL) < 0 && GetKeyState(VK_MENU) < 0) {
        if (d && !(lp & (1 << 30))) toggle_fullscreen(*d);
        return 0;
      }
      if (in) in->key_down(static_cast<unsigned>(wp), lp);
      // Alt / F10はここで止め、（存在しない）ウィンドウメニューを開かずにホストへ
      // 届くようにする。Alt+F4は手元で使えるように残す。
      if (msg == WM_SYSKEYDOWN && wp == VK_F4) break;
      return 0;
    case WM_KEYUP:
    case WM_SYSKEYUP:
      if (in) in->key_up(static_cast<unsigned>(wp), lp);
      return 0;
    case WM_CHAR:
      if (in) in->char_input(static_cast<wchar_t>(wp));
      return 0;
    case WM_SYSCHAR:
      return 0;  // Alt+文字。WM_SYSKEYDOWNで送り済み
    case WM_APP_GRABBED_KEY:
      for (const input::GrabbedKey& k : g_app.grab.take()) {
        if (g_app.log_input) {
          log::info("input: grabbed key {} vk 0x{:02x}, {} ms after the hook saw it", k.down ? "down" : "up", k.vk,
                    static_cast<LONG>(GetTickCount() - k.time));
        }
        dispatch_keys_before(k.time);
        if (!in) continue;
        if (k.down) {
          in->key_down(k.vk, k.lparam());
        } else {
          in->key_up(k.vk, k.lparam());
        }
      }
      return 0;
    case WM_MOUSEMOVE:
      mouse_to_canvas(lp);
      return 0;
    case WM_LBUTTONDOWN: case WM_RBUTTONDOWN: case WM_MBUTTONDOWN:
      SetFocus(hwnd);
      if (GetCapture() != hwnd) g_app.drag_view = d;
      SetCapture(hwnd);
      mouse_to_canvas(lp);
      if (in) in->button(msg == WM_LBUTTONDOWN ? 0 : msg == WM_RBUTTONDOWN ? 1 : 2, true);
      return 0;
    case WM_LBUTTONUP: case WM_RBUTTONUP: case WM_MBUTTONUP:
      mouse_to_canvas(lp);
      if (in) in->button(msg == WM_LBUTTONUP ? 0 : msg == WM_RBUTTONUP ? 1 : 2, false);
      if (!(wp & (MK_LBUTTON | MK_RBUTTON | MK_MBUTTON))) ReleaseCapture();
      return 0;
    case WM_CAPTURECHANGED:
      if (reinterpret_cast<HWND>(lp) != hwnd) g_app.drag_view = nullptr;
      return 0;
    case WM_MOUSEWHEEL:
      if (in) in->wheel(GET_WHEEL_DELTA_WPARAM(wp) / double(WHEEL_DELTA), now_ms());
      return 0;
    case WM_SETFOCUS:
      g_app.grab.set_focused(true);
      return 0;
    case WM_KILLFOCUS:
      g_app.grab.set_focused(false);
      if (in) in->release_all();
      return 0;
    case WM_SIZE:
      if (d && d->render_ok) {
        try {
          d->renderer.resize(LOWORD(lp), HIWORD(lp));
        } catch (const std::exception& e) {
          log::error("resize: {}", e.what());
        }
      }
      return 0;
    case WM_ERASEBKGND:
      return 1;  // スワップチェーンがビュー全体を覆う
    case WM_SETCURSOR:
      if (LOWORD(lp) == HTCLIENT && d && d->cursor) {
        SetCursor(d->cursor);
        return TRUE;
      }
      break;
  }
  return DefWindowProcW(hwnd, msg, wp, lp);
}

void switch_quality(int mode);

LRESULT CALLBACK main_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
  switch (msg) {
    case WM_SYSCOMMAND:
      if ((wp & 0xFFF0) == kSysCmdFullscreen) {
        toggle_fullscreen(primary());
        return 0;
      }
      break;
    case WM_COMMAND: {
      const UINT id = LOWORD(wp);
      if (id > kCmdModeBase && id - kCmdModeBase < mode_choices().size()) {
        switch_quality(static_cast<int>(id - kCmdModeBase));
        return 0;
      }
      break;
    }
    case WM_INITMENUPOPUP:
      if (reinterpret_cast<HMENU>(wp) == g_app.quality_menu) {
        const bool live = g_app.session_up && g_app.session->alive();
        for (UINT i = 1; i < mode_choices().size(); ++i) {
          EnableMenuItem(g_app.quality_menu, kCmdModeBase + i, MF_BYCOMMAND | (live ? MF_ENABLED : MF_GRAYED));
        }
        return 0;
      }
      break;
    case WM_SIZE:
      primary().minimized = wp == SIZE_MINIMIZED;
      if (g_app.status && primary().view) layout_children();
      return 0;
    case WM_SETFOCUS:
      if (primary().view) SetFocus(primary().view);  // キーボード入力は描画ビューへ
      return 0;
    case WM_GETMINMAXINFO: {
      auto* mm = reinterpret_cast<MINMAXINFO*>(lp);
      mm->ptMinTrackSize = {320, 240};
      return 0;
    }
    case WM_WTSSESSION_CHANGE:
      // Win+Lはグラブ中でもWindowsをロックする。ロック画面がキーの解放を受け取って
      // しまうので、ここですべて離す。
      if (wp == WTS_SESSION_LOCK) {
        g_app.grab.reset();
        if (g_app.input) g_app.input->release_all();
      }
      return 0;
    case WM_DESTROY:
      WTSUnRegisterSessionNotification(hwnd);
      PostQuitMessage(0);
      return 0;
  }
  return DefWindowProcW(hwnd, msg, wp, lp);
}

// 2枚目のディスプレイのウィンドウ。中身はビューだけ。閉じるとメインウィンドウを
// 閉じたときと同じくビューアを終える。
LRESULT CALLBACK second_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
  DisplayView* d = display_of(hwnd);
  switch (msg) {
    case WM_SYSCOMMAND:
      if ((wp & 0xFFF0) == kSysCmdFullscreen && d) {
        toggle_fullscreen(*d);
        return 0;
      }
      break;
    case WM_SIZE:
      if (d) {
        d->minimized = wp == SIZE_MINIMIZED;
        if (d->view) MoveWindow(d->view, 0, 0, LOWORD(lp), std::max<int>(1, HIWORD(lp)), TRUE);
      }
      return 0;
    case WM_SETFOCUS:
      if (d && d->view) SetFocus(d->view);
      return 0;
    case WM_GETMINMAXINFO: {
      auto* mm = reinterpret_cast<MINMAXINFO*>(lp);
      mm->ptMinTrackSize = {320, 240};
      return 0;
    }
    case WM_CLOSE:
      DestroyWindow(g_app.main);
      return 0;
  }
  return DefWindowProcW(hwnd, msg, wp, lp);
}

bool register_classes() {
  WNDCLASSEXW wc{sizeof(wc)};
  wc.hInstance = g_app.inst;
  wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
  wc.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
  wc.lpfnWndProc = main_proc;
  wc.lpszClassName = kMainClass;
  wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
  if (!RegisterClassExW(&wc)) return false;
  wc.lpfnWndProc = second_proc;
  wc.lpszClassName = kSecondClass;
  if (!RegisterClassExW(&wc)) return false;
  wc.lpfnWndProc = view_proc;
  wc.lpszClassName = kViewClass;
  wc.hbrBackground = nullptr;
  wc.style = CS_HREDRAW | CS_VREDRAW;
  return RegisterClassExW(&wc) != 0;
}

rfb::VirtualDisplayParams fit_to_host(int points_w, int points_h, double scale);

struct Args {
  ConnectSettings settings;
  std::wstring gpu_spec;
  bool list_gpus = false;
  int smoke_seconds = 0;  // --smoke N。ダイアログを出さず、N秒描画して終わる
  std::wstring play_path;
  bool software_decode = false;
  std::wstring screenshot;  // --screenshot PATH.bmp。--smokeの終了時に保存する
  bool connect_now = false;
  bool password_stdin = false;  // --connectで、標準入力の1行目をパスワードにする
  bool alt_session = false;
  bool no_curtain = false;
  bool input_test = false;  // 接続後、Macのポインタを円を描くように動かす（診断用）
  bool perf = false;        // フレームのタイミングをログに出す
  bool wake_test = false;   // 映像が2分止まったらMacのディスプレイを起こし、30秒後に終わる
  bool standard = false;    // 画面共有の標準モード。フレームバッファ更新で受け、UDPのメディアなし
  std::vector<int32_t> encodings;  // --encodings 1002,6,16。標準モードのSetEncodings
  std::wstring quality = L"thousands";  // --quality adaptive|bw|gray|thousands|millions（標準モード）
  std::wstring dump_records;       // --dump-records PATH。制御チャネルのレコード（解析用）
  bool legacy_cursor = false;
  std::optional<rfb::VirtualDisplayParams> advertise;  // --advertise WxH[@S]。固定
  bool hevc_probe = false;
  bool hevc = false;  // --hevc [WxH@S]。HEVC 4:4:4をIntel Quick Syncでデコードする
  bool hevc420 = false;  // --hevc420 WxH@S。同じことをHEVC 4:2:0で、--gpuのGPU（D3D11VA）で行う
  bool h264 = false;     // --h264。ダイアログのコーデックに関係なくH.264を使う
  bool resize_test = false;  // 接続後、3秒でウィンドウを縮め、9秒で元に戻す
  bool keyboard_grab = true;
  bool key_test = false;  // 接続後または再生中にテスト用のキーを送り、送ったkeysymをログに出す
  bool log_input = false;  // 入力のタイミングと送った内容をログに出す
  bool view_only = false;  // このPCのキーボードとマウスの入力を送らない
  bool log_file = false;   // --log。既定はオフ
  std::optional<int> displays;  // --displays 1|2。既定はダイアログの選択
  bool fullscreen = false;
  net::Family family = net::Family::Any;  // --ipv4 / --ipv6
};

Args parse_args() {
  Args a;
  int argc = 0;
  LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
  std::wstring advertise;  // --advertise / --hevcのWxH@S。フラグがすべて分かってから読む
  for (int i = 1; i < argc; ++i) {
    std::wstring k = argv[i];
    auto next = [&]() -> std::wstring { return i + 1 < argc ? argv[++i] : L""; };
    if (k == L"--host") a.settings.host = next();
    else if (k == L"--port") a.settings.port = _wtoi(next().c_str());
    else if (k == L"--user") a.settings.user = next();
    else if (k == L"--gpu") a.gpu_spec = next();
    else if (k == L"--list-gpus") a.list_gpus = true;
    else if (k == L"--smoke") a.smoke_seconds = _wtoi(next().c_str());
    else if (k == L"--play") a.play_path = next();
    else if (k == L"--software-decode") a.software_decode = true;
    else if (k == L"--screenshot") a.screenshot = next();
    else if (k == L"--connect") a.connect_now = true;
    else if (k == L"--password-stdin") a.password_stdin = a.connect_now = true;
    else if (k == L"--alt-session") a.alt_session = true;
    else if (k == L"--no-curtain") a.no_curtain = true;
    else if (k == L"--input-test") a.input_test = true;
    else if (k == L"--perf") a.perf = true;
    else if (k == L"--wake-test") a.wake_test = true;
    else if (k == L"--standard") a.standard = true;
    else if (k == L"--quality") a.quality = next(), a.standard = true;
    else if (k == L"--dump-records") a.dump_records = next();
    else if (k == L"--encodings") {
      const std::wstring v = next();
      for (size_t pos = 0; pos <= v.size();) {
        const size_t end = std::min(v.find(L',', pos), v.size());
        if (end > pos) a.encodings.push_back(_wtoi(v.substr(pos, end - pos).c_str()));
        pos = end + 1;
      }
    }
    else if (k == L"--legacy-cursor") a.legacy_cursor = true;
    else if (k == L"--resize-test") a.resize_test = true;
    else if (k == L"--no-keyboard-grab") a.keyboard_grab = false;
    else if (k == L"--key-test") a.key_test = true;
    else if (k == L"--log-input") a.log_input = true;
    else if (k == L"--view-only") a.view_only = true;
    else if (k == L"--log") a.log_file = true;
    else if (k == L"--displays") a.displays = std::clamp(_wtoi(next().c_str()), 1, kMaxDisplays);
    else if (k == L"--fullscreen") a.fullscreen = true;
    else if (k == L"--ipv4") a.family = net::Family::V4;
    else if (k == L"--ipv6") a.family = net::Family::V6;
    else if (k == L"--hevc-probe" || k == L"--hevc" || k == L"--hevc420") {
      (k == L"--hevc-probe" ? a.hevc_probe : a.hevc) = true;
      a.hevc420 = k == L"--hevc420";
      // 省略できるWxH@SCALE。--advertiseと同じく、そのサイズで固定する。
      if (i + 1 < argc && argv[i + 1][0] >= L'0' && argv[i + 1][0] <= L'9') advertise = next();
      if (a.hevc_probe) a.displays = 1;  // 最初のストリームしか読まない
    }
    else if (k == L"--advertise") advertise = next();
    else if (k == L"--h264") a.h264 = true;
    else if (k == L"--verbose") log::set_min_level(log::Level::Debug);
  }
  LocalFree(argv);
  // これらはログでしか結果を出さない。
  if (a.perf || a.log_input || a.key_test || a.smoke_seconds > 0) a.log_file = true;
  // ループの後に置く。fit_to_hostの上限はコーデックで変わり、そのフラグの位置は決まっていない。
  g_app.hevc = a.hevc || a.hevc_probe;
  int w = 0, h = 0;
  double s = 1.0;
  if (swscanf_s(advertise.c_str(), L"%dx%d@%lf", &w, &h, &s) >= 2 && w > 0 && h > 0 && s >= 1.0 && s <= 4.0) {
    a.advertise = fit_to_host(w, h, s);
  }
  return a;
}

// WIN32サブシステムのexeにはコンソールがないので、CLIの出力には親のコンソールを借りる。
void print_to_parent_console(const std::wstring& text) {
  // リダイレクトした標準出力（パイプ、ファイル）は、GUIサブシステムのexeにも引き継がれる。
  HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
  DWORD type = out && out != INVALID_HANDLE_VALUE ? GetFileType(out) : FILE_TYPE_UNKNOWN;
  if (type == FILE_TYPE_PIPE || type == FILE_TYPE_DISK) {
    std::string s = narrow(text);
    DWORD written = 0;
    WriteFile(out, s.data(), static_cast<DWORD>(s.size()), &written, nullptr);
    return;
  }
  if (AttachConsole(ATTACH_PARENT_PROCESS)) {
    FILE* f = nullptr;
    _wfreopen_s(&f, L"CONOUT$", L"w", stdout);
    std::string s = narrow(text);
    std::fwrite(s.data(), 1, s.size(), stdout);
    std::fflush(stdout);
  } else {
    MessageBoxW(nullptr, text.c_str(), L"iShareScreen", MB_ICONINFORMATION);
  }
}

// --password-stdin。（リダイレクトした）標準入力の1行目。
std::optional<std::wstring> read_stdin_password() {
  HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
  if (!in || in == INVALID_HANDLE_VALUE) return std::nullopt;
  std::string line;
  char c = 0;
  DWORD n = 0;
  while (ReadFile(in, &c, 1, &n, nullptr) && n == 1 && c != '\n') line.push_back(c);
  if (!line.empty() && line.back() == '\r') line.pop_back();
  if (line.starts_with("\xEF\xBB\xBF")) line.erase(0, 3);  // シェルによってはUTF-8のBOMが付く
  if (line.empty()) return std::nullopt;
  std::wstring w = widen(line);
  secure_wipe(line);
  return w;
}

// H.264では、ホストが描画するバッキングストアは最大3840x2160で、それより大きいと
// 小さな既定値（960x540ポイント）に戻す。また、実際に受け付けた拡大率は整数だけ
// だった。ディスクリプタの最大サイズを上げると大きなディスプレイ（4320x2324で
// 試した）にはなるが、映像は来ない。H.264のレベル5.2のフレームサイズを超えると、
// エンコーダーが起動しないため。HEVCの4本のストリップは、ディスクリプタの最大値も
// 合わせて上げると7680x4320（各ストリップがレベル6.0）まで上がった。
// Pythonのデスクトップビューア（_resolve_hidpi_request）と同じ決まりで、HiDPIの
// クライアントなら2倍、それ以外は1倍にし、バッキングが収まるまでポイントサイズを
// 縦横比を保って縮める。
constexpr int kHostMaxBackingW = 3840, kHostMaxBackingH = 2160;
constexpr int kHevcMaxBackingW = 7680, kHevcMaxBackingH = 4320;
constexpr int kMinAdvertiseW = 640, kMinAdvertiseH = 480;

rfb::VirtualDisplayParams fit_to_host(int points_w, int points_h, double scale) {
  rfb::VirtualDisplayParams d;
  const int max_w = g_app.hevc ? kHevcMaxBackingW : kHostMaxBackingW;
  const int max_h = g_app.hevc ? kHevcMaxBackingH : kHostMaxBackingH;
  const double fit = std::min({max_w / scale / std::max(1, points_w), max_h / scale / std::max(1, points_h), 1.0});
  d.width = std::max(kMinAdvertiseW, static_cast<int>(points_w * fit) & ~1);
  d.height = std::max(kMinAdvertiseH, static_cast<int>(points_h * fit) & ~1);
  d.hidpi_scale = scale;
  d.max_width = std::max(d.max_width, static_cast<int>(std::lround(d.width * scale)));
  d.max_height = std::max(d.max_height, static_cast<int>(std::lround(d.height * scale)));
  return d;
}

bool auto_resolution(const ConnectSettings& s) {
  const auto& choices = resolution_choices();
  return choices[std::min<size_t>(static_cast<size_t>(std::max(0, s.resolution)), choices.size() - 1)].width == 0;
}

// 「自動」のときは描画ビューのサイズをポイント（ピクセル / Windowsの表示スケール）で
// 返す。こうするとMacのUI要素がWindowsのものと同じ大きさになり、映像も伸縮せずに
// ビューに対応する。固定の選択肢なら選んだとおりに使う。
rfb::VirtualDisplayParams display_for(const ConnectSettings& s, HWND view) {
  const auto& choices = resolution_choices();
  const ResolutionChoice& r = choices[std::min<size_t>(static_cast<size_t>(std::max(0, s.resolution)), choices.size() - 1)];
  if (r.width > 0) return fit_to_host(r.width, r.height, r.hidpi_scale);
  RECT rc{};
  GetClientRect(view, &rc);
  const double dpi_scale = std::max(1.0, GetDpiForWindow(view) / 96.0);
  const double scale = dpi_scale >= 1.5 ? 2.0 : 1.0;  // Pythonクライアントのround(content scale)と同じ
  return fit_to_host(static_cast<int>(std::lround(rc.right / dpi_scale)),
                     static_cast<int>(std::lround(rc.bottom / dpi_scale)), scale);
}

void note_advertised(DisplayView& d) {
  RECT rc{};
  GetClientRect(d.view, &rc);
  d.adv_w = rc.right;
  d.adv_h = rc.bottom;
  d.adv_dpi = GetDpiForWindow(d.view);
  d.pending_w = -1;
}

// 自動解像度。ビューが新しいサイズに落ち着いたら（または別の拡大率のモニターに
// 移ったら）、Macに合ったディスプレイを要求する。2枚あるときは両方を、それぞれ
// 自分のウィンドウのサイズで要求する。
void track_view_size(const ConnectSettings& s) {
  if (!g_app.dynamic_resolution || !g_app.session->alive()) return;
  const auto now = std::chrono::steady_clock::now();
  bool settled = false;
  for (int i = 0; i < g_app.n_displays; ++i) {
    DisplayView& d = g_app.displays[i];
    if (d.minimized) return;
    RECT rc{};
    GetClientRect(d.view, &rc);
    if (rc.right <= 0 || rc.bottom <= 0) return;
    const UINT dpi = GetDpiForWindow(d.view);
    const bool differs = std::abs(rc.right - d.adv_w) >= kResizeMinDeltaPx ||
                         std::abs(rc.bottom - d.adv_h) >= kResizeMinDeltaPx || dpi != d.adv_dpi;
    if (!differs) {
      d.pending_w = -1;
      continue;
    }
    if (rc.right != d.pending_w || rc.bottom != d.pending_h || dpi != d.pending_dpi) {
      d.pending_w = rc.right;
      d.pending_h = rc.bottom;
      d.pending_dpi = dpi;
      d.pending_since = now;
      continue;
    }
    if (now - d.pending_since >= kResizeDebounce) settled = true;
  }
  if (!settled || now - g_app.last_resize_request < kResizeMinInterval) return;
  // まだディスプレイを作り直している最中に要求すると、Macは小さな代わりの
  // ディスプレイ（800x600）か、始まらないストリームで答えてきた。
  for (int i = 0; i < g_app.n_displays; ++i) {
    const DisplayView& d = g_app.displays[i];
    if (d.change.active() || now - d.change_done < kResizeSettle) return;
  }
  const rfb::VirtualDisplayParams first = display_for(s, primary().view);
  std::optional<rfb::VirtualDisplayParams> second;
  if (g_app.n_displays > 1) second = display_for(s, g_app.displays[1].view);
  g_app.session->request_resolution(first, second);
  const uint64_t layouts = g_app.session->layouts_received();
  for (int i = 0; i < g_app.n_displays; ++i) {
    DisplayView& d = g_app.displays[i];
    note_advertised(d);
    const rfb::VirtualDisplayParams& p = i == 0 ? first : *second;
    d.asked_w = p.width;
    d.asked_h = p.height;
    d.asked_layouts = layouts;
    // 標準モードは画面をそのまま描き直すので、再起動を待つ必要はない。
    if (!g_app.session->standard_mode()) d.change.requested(now, layouts);
  }
  g_app.last_resize_request = now;
}

constexpr wchar_t kDisplayChangeNotice[] = L"Mac の画面サイズを切り替えています…";

// 高パフォーマンス。Macのレイアウトと届いた映像から、各ビューのディスプレイ変更の
// 表示を出したり消したりする（DisplayChange）。
void follow_display_changes(const std::vector<rfb::DisplayRect>& rects) {
  const auto now = std::chrono::steady_clock::now();
  const uint64_t layouts = g_app.session->layouts_received();
  for (int i = 0; i < g_app.n_displays; ++i) {
    DisplayView& d = g_app.displays[i];
    if (i < static_cast<int>(rects.size()) && d.change.on_layout(now, layouts, rects[i].w, rects[i].h)) {
      log::info("window {}: the Mac changed its display to {}x{} pixels", i + 1, rects[i].w, rects[i].h);
    }
    if (d.change.expired(now)) {
      log::warn("window {}: no picture of the new size in 10 s; notice taken down", i + 1);
      d.change_done = now;
    }
    // 前回の要求への答え。サイズが違えばそれはMacの代わりのサイズで、ウィンドウの
    // サイズではない。伝えたサイズを忘れ、track_view_sizeにもう一度要求させる。
    // 続けて要求し直すのは2回まで。
    if (d.asked_w && layouts > d.asked_layouts && i < static_cast<int>(rects.size())) {
      const rfb::DisplayRect& r = rects[i];
      const bool same = std::abs(r.pw - d.asked_w) <= 2 && std::abs(r.ph - d.asked_h) <= 2;
      if (same) {
        d.asked_again = 0;
      } else if (d.asked_again < kAskAgainMax) {
        log::warn("window {}: asked the Mac for {}x{} points, it made {}x{}; asking again", i + 1, d.asked_w,
                  d.asked_h, r.pw, r.ph);
        ++d.asked_again;
        d.adv_w = d.adv_h = 0;
      } else {
        log::warn("window {}: the Mac made {}x{} points instead of {}x{} again; keeping it", i + 1, r.pw, r.ph,
                  d.asked_w, d.asked_h);
      }
      d.asked_w = 0;
    }
  }
}

void display_frame_shown(DisplayView& d, int w, int h, int tiles) {
  const auto since = d.change.since();
  if (d.change.on_frame(w, h, tiles)) {
    d.change_done = std::chrono::steady_clock::now();
    log::info("window {}: {}x{} picture{} {:.1f} s after the display change began", &d - g_app.displays + 1, w,
              h, tiles > 1 ? std::format(" strip (of {})", tiles) : "",
              std::chrono::duration<double>(d.change_done - since).count());
  }
}

// 標準モードのSetEncodings。選んだ画質のコーデックを先頭に置き（ホストは対応する
// 最初のものを使う）、動いたウィンドウ用のCopyRect、代わりのコーデックを続け、
// 最後に疑似エンコーディングを並べる。カーソル形状、ディスプレイのレイアウト、
// keysym、入力ソース、デバイス情報、DesktopSize、Appleの1100/1101。
std::vector<int32_t> standard_encodings(const std::wstring& quality) {
  std::vector<int32_t> e;
  if (quality == L"bw") e = {1000};
  else if (quality == L"gray") e = {1001};
  else if (quality == L"millions") e = {16, 6};
  else if (quality == L"adaptive") e = {1011};
  else e = {1002};
  for (int32_t x : {1, 1002, 16, 6}) {
    if (std::find(e.begin(), e.end(), x) == e.end()) e.push_back(x);
  }
  for (int32_t x : {1104, 1105, 1107, 1109, 1110, -223, 1100, 1101}) e.push_back(x);
  return e;
}

// 接続するモード。--standard / --qualityがあればそれ、なければダイアログの選択。
// 知らない--qualityは、standard_encodings()と同じくthousandsにする。
int mode_from(const Args& args) {
  const auto& c = mode_choices();
  if (!args.standard) return std::clamp(args.settings.mode, 0, static_cast<int>(c.size()) - 1);
  int thousands = 0;
  for (size_t i = 1; i < c.size(); ++i) {
    if (c[i].quality == args.quality) return static_cast<int>(i);
    if (c[i].quality == L"thousands") thousands = static_cast<int>(i);
  }
  return thousands;
}

// 要求するディスプレイの数。2枚にするのは高パフォーマンスでカーテンありのとき
// （仮想ディスプレイ）だけで、--displaysかダイアログの選択に従う。
int displays_from(const Args& args, bool standard) {
  const int want = args.displays.value_or(args.settings.two_displays ? 2 : 1);
  if (want < 2) return 1;
  if (standard || args.no_curtain || !args.settings.curtain) {
    log::warn("two displays need high performance with the curtain on; showing one");
    return 1;
  }
  return 2;
}

// ステータスバー用。高パフォーマンス、または標準とその画質。
std::wstring mode_label() {
  const ModeChoice& m = mode_choices()[g_app.mode];
  if (!m.quality.empty()) return std::format(L"標準 ({})", m.name);
  return g_app.n_displays > 1 ? m.name + L" (2 画面)" : m.name;
}

void check_quality_menu() {
  for (UINT i = 1; i < mode_choices().size(); ++i) {
    CheckMenuItem(g_app.quality_menu, kCmdModeBase + i,
                  MF_BYCOMMAND | (static_cast<int>(i) == g_app.mode ? MF_CHECKED : MF_UNCHECKED));
  }
}

// 標準モードのメニューバー。画質を、画面共有と同じく接続中に切り替えられる（高画質と
// 適応を先に置く）。その後にApple Remote Desktopの古い色数の選択肢を並べる。
HMENU build_quality_menu() {
  const auto& c = mode_choices();
  g_app.quality_menu = CreatePopupMenu();
  for (const wchar_t* q : {L"millions", L"adaptive", L"", L"thousands", L"gray", L"bw"}) {
    if (!*q) {
      AppendMenuW(g_app.quality_menu, MF_SEPARATOR, 0, nullptr);
      continue;
    }
    for (UINT i = 1; i < c.size(); ++i) {
      if (c[i].quality != q) continue;
      MENUITEMINFOW mi{sizeof(mi)};
      mi.fMask = MIIM_FTYPE | MIIM_ID | MIIM_STRING;
      mi.fType = MFT_STRING | MFT_RADIOCHECK;
      mi.wID = kCmdModeBase + i;
      mi.dwTypeData = const_cast<wchar_t*>(c[i].name.c_str());
      InsertMenuItemW(g_app.quality_menu, GetMenuItemCount(g_app.quality_menu), TRUE, &mi);
    }
  }
  check_quality_menu();
  HMENU bar = CreateMenu();
  AppendMenuW(bar, MF_POPUP, reinterpret_cast<UINT_PTR>(g_app.quality_menu), L"画質");
  return bar;
}

// 画質メニューから呼ぶ。残りのセッションで使うエンコーディングと、次回の接続の
// モードを変える。
void switch_quality(int mode) {
  const auto& c = mode_choices();
  if (mode <= 0 || mode >= static_cast<int>(c.size()) || mode == g_app.mode) return;
  if (!g_app.session_up || !g_app.session->alive() || !g_app.session->standard_mode()) return;
  log::info("quality: {} -> {}", narrow(c[g_app.mode].quality), narrow(c[mode].quality));
  g_app.session->set_encodings(standard_encodings(c[mode].quality));
  g_app.mode = mode;
  check_quality_menu();
  save_mode(mode);
}

// ビューアのウィンドウを置く場所。メインのウィンドウは、マウスの下にあるモニターの
// 作業領域の約85%の大きさで中央に置く。ひと目でウィンドウと分かり、（自動解像度では）
// Macのディスプレイもこのサイズになる。2枚目のディスプレイのウィンドウは、別の
// モニターに同じように置く。モニターが1台だけなら、Macがディスプレイを並べるのと
// 同じように、2つを左右に並べて分け合う。
struct Placement {
  RECT main{}, second{};
};

Placement place_windows(int displays) {
  POINT cursor_pos{};
  GetCursorPos(&cursor_pos);
  const HMONITOR home = MonitorFromPoint(cursor_pos, MONITOR_DEFAULTTOPRIMARY);
  MONITORINFO mi{sizeof(mi)};
  GetMonitorInfoW(home, &mi);
  auto centred = [](const RECT& wa) {
    const int w = (wa.right - wa.left) * 85 / 100, h = (wa.bottom - wa.top) * 85 / 100;
    const int x = wa.left + (wa.right - wa.left - w) / 2, y = wa.top + (wa.bottom - wa.top - h) / 2;
    return RECT{x, y, x + w, y + h};
  };
  Placement p;
  p.main = centred(mi.rcWork);
  if (displays < 2) return p;
  struct Find {
    HMONITOR home;
    std::optional<RECT> other;
  } find{home, std::nullopt};
  EnumDisplayMonitors(
      nullptr, nullptr,
      [](HMONITOR m, HDC, LPRECT, LPARAM lp) -> BOOL {
        auto* f = reinterpret_cast<Find*>(lp);
        if (m == f->home) return TRUE;
        MONITORINFO info{sizeof(info)};
        GetMonitorInfoW(m, &info);
        f->other = info.rcWork;
        return FALSE;
      },
      reinterpret_cast<LPARAM>(&find));
  if (find.other) {
    p.second = centred(*find.other);
  } else {
    const RECT& wa = mi.rcWork;
    const int half = (wa.right - wa.left) / 2;
    p.main = RECT{wa.left, wa.top, wa.left + half, wa.bottom};
    p.second = RECT{wa.left + half, wa.top, wa.right, wa.bottom};
  }
  return p;
}

// 隠れているウィンドウを、アクティブにせずに動かす。
void place_hidden(HWND w, const RECT& r) {
  SetWindowPos(w, nullptr, r.left, r.top, r.right - r.left, r.bottom - r.top, SWP_NOZORDER | SWP_NOACTIVATE);
}

void add_fullscreen_menu_item(HWND frame) {
  HMENU sys = GetSystemMenu(frame, FALSE);
  AppendMenuW(sys, MF_SEPARATOR, 0, nullptr);
  AppendMenuW(sys, MF_STRING, kSysCmdFullscreen, L"全画面表示\tCtrl+Alt+Enter");
}

// 2枚目のディスプレイのウィンドウ。接続するまで隠しておく。2枚のディスプレイを
// 要求する接続のときに初めて作る。
void create_second_window(const RECT& r) {
  DisplayView& d = g_app.displays[1];
  d.frame = CreateWindowExW(0, kSecondClass, L"", WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN, r.left, r.top,
                            r.right - r.left, r.bottom - r.top, nullptr, nullptr, g_app.inst, nullptr);
  d.view = CreateWindowExW(0, kViewClass, nullptr, WS_CHILD | WS_VISIBLE, 0, 0, 1, 1, d.frame, nullptr, g_app.inst,
                           nullptr);
  RECT rc{};
  GetClientRect(d.frame, &rc);
  MoveWindow(d.view, 0, 0, rc.right, std::max(1L, rc.bottom), TRUE);
  add_fullscreen_menu_item(d.frame);
  g_app.grab.add_window(d.frame, d.view);
}

// 接続の前に、選んだ設定に合わせて（隠れた）ウィンドウを用意する。数、位置、
// メニュー、タイトル、全画面。こうして、要求する解像度を、表示したときのウィンドウの
// サイズに合わせる。
void configure_viewer(const Args& args) {
  g_app.mode = mode_from(args);
  const bool standard = !mode_choices()[g_app.mode].quality.empty();
  g_app.n_displays = displays_from(args, standard);
  for (DisplayView& d : g_app.displays) {
    if (d.frame && d.fullscreen) leave_fullscreen(d);  // 前回の試行のもの
  }
  g_app.menu_bar = standard ? g_app.quality_bar : nullptr;
  SetMenu(g_app.main, g_app.menu_bar);
  check_quality_menu();
  SetWindowTextW(g_app.main, std::format(L"iShareScreen — {}", args.settings.host).c_str());
  const Placement place = place_windows(g_app.n_displays);
  place_hidden(g_app.main, place.main);
  layout_children();
  if (g_app.n_displays > 1) {
    if (!g_app.displays[1].frame) {
      create_second_window(place.second);
    } else {
      place_hidden(g_app.displays[1].frame, place.second);
    }
    SetWindowTextW(g_app.displays[1].frame, std::format(L"iShareScreen — {} (2)", args.settings.host).c_str());
  }
  if (args.fullscreen) toggle_fullscreen(primary());
}

// 接続した。選んだGPUでレンダラーを作り、ウィンドウを表示する。
void show_viewer(int show, int gpu) {
  for (int i = 0; i < g_app.n_displays; ++i) {
    DisplayView& d = g_app.displays[i];
    if (d.render_ok) continue;
    try {
      d.renderer.init(d.view, gpu);
      d.render_ok = true;
    } catch (const std::exception& e) {
      log::error("renderer init failed: {}", e.what());
      set_status(L"D3D11 の初期化に失敗しました: " + widen(e.what()));
    }
  }
  for (int i = 1; i < g_app.n_displays; ++i) ShowWindow(g_app.displays[i].frame, SW_SHOWNOACTIVATE);
  ShowWindow(g_app.main, show);
  UpdateWindow(g_app.main);
  SetForegroundWindow(g_app.main);
  SetFocus(primary().view);
}

// バックグラウンドで接続する。結果はWM_APP_CONNECT_RESULTで`notify`（接続
// ダイアログ、--connectのときはメインウィンドウ）に送る。
void start_session(Args& args, HWND notify) {
  ConnectSettings& s = args.settings;
  session::SessionOptions so;
  so.host = narrow(s.host);
  so.port = static_cast<uint16_t>(s.port);
  so.family = args.family;
  so.username = narrow(s.user);
  so.password = narrow(s.password);
  wipe(s.password);
  const std::wstring& quality = mode_choices()[g_app.mode].quality;
  const bool standard = !quality.empty();
  // --hevc / --hevc420 / --h264はダイアログのコーデックより優先する。
  const auto& codecs = codec_choices();
  const CodecChoice& codec = codecs[std::clamp(s.codec, 0, static_cast<int>(codecs.size()) - 1)];
  so.hevc = !standard && !args.h264 && (args.hevc || codec.hevc);
  so.hevc420 = so.hevc && (args.hevc ? args.hevc420 : codec.hevc420);
  g_app.hevc = so.hevc || args.hevc_probe;  // display_forより前に。fit_to_hostの上限を上げる
  so.display = args.advertise ? *args.advertise : display_for(s, primary().view);
  if (g_app.n_displays > 1) so.display2 = args.advertise ? *args.advertise : display_for(s, g_app.displays[1].view);
  // カーテンがないとMac本体の画面が映る。解像度を要求すると、その代わりに
  // 仮想ディスプレイが置かれてしまう。
  g_app.dynamic_resolution = !args.advertise && auto_resolution(s) && s.curtain && !args.no_curtain;
  for (int i = 0; i < g_app.n_displays; ++i) {
    DisplayView& d = g_app.displays[i];
    note_advertised(d);
    if (!g_app.dynamic_resolution) continue;
    const rfb::VirtualDisplayParams& p = i == 0 ? so.display : *so.display2;
    d.asked_w = p.width;  // セッションの最初のレイアウトと照らし合わせる
    d.asked_h = p.height;
    d.asked_layouts = 0;
    d.asked_again = 0;
  }
  so.curtain = s.curtain && !args.no_curtain;
  so.legacy_cursor = args.legacy_cursor;
  so.perf = args.perf;
  so.media = !standard;
  so.encodings = args.encodings.empty() && standard ? standard_encodings(quality) : args.encodings;
  so.dump_path = args.dump_records;
  so.log_input = args.log_input;
  so.hevc_probe = args.hevc_probe;
  so.alt_session = args.alt_session;
  so.adapter_index = s.gpu;
  so.prefer_hwaccel = !args.software_decode;
  // Macに別の人がログインしている。その人の画面を共有する（相手に許可の
  // ポップアップが出る）か、自分のセッションを開く。
  so.on_session_choice = [](const std::string& console_user) {
    const std::wstring text = std::format(
        L"Mac には別のユーザー ({}) がログインしています。\n\n"
        L"はい: その画面を共有します (Mac 側で許可が必要です)\n"
        L"いいえ: 自分のユーザーで別のセッションを開きます",
        widen(console_user));
    const int r = MessageBoxW(nullptr, text.c_str(), L"iShareScreen", MB_YESNO | MB_ICONQUESTION | MB_TOPMOST | MB_SETFOREGROUND);
    return r == IDNO ? proto::SessionChoice::AltSession : proto::SessionChoice::ShareConsole;
  };
  log::info("connecting to {}:{} as {} (display {}x{}@{}{}, curtain {})", so.host, so.port, so.username,
            so.display.width, so.display.height, so.display.hidpi_scale,
            so.display2 ? std::format(" + {}x{}@{}", so.display2->width, so.display2->height, so.display2->hidpi_scale)
                        : "",
            so.curtain ? "on" : "off");
  g_app.host_label = std::format(L"{}:{}", s.host, s.port);
  set_status(std::format(L"{} に接続しています… ({})", g_app.host_label, mode_label()));

  g_app.session = std::make_shared<session::Session>(std::move(so));
  g_app.connecting = true;
  std::thread([sess = g_app.session, notify] {
    std::wstring* why = nullptr;
    try {
      sess->connect();
    } catch (const std::exception& e) {
      log::error("connect failed: {}", e.what());
      why = new std::wstring(widen(e.what()));
    }
    g_app.connecting = false;
    if (!PostMessageW(notify, WM_APP_CONNECT_RESULT, why ? 0 : 1, reinterpret_cast<LPARAM>(why))) delete why;
  }).detach();
}

// --key-test。打鍵したのと同じようにキーを送り込む。再生中（Macには何も届かない）は
// a、Win+、bを一度に送り、それでもa / Cmd押下 / , / Cmd解放 / bの順に出なければ
// ならない。Macにつないでいるときは、打鍵程度の間隔で1回の呼び出しにつき1ステップ
// ずつWin+Spaceを送り、Mac側でSpotlightを開く。
struct TestKey {
  WORD vk;
  bool down;
};
const std::vector<TestKey> kKeyTestBurst = {{'A', true},           {'A', false},     {VK_LWIN, true}, {VK_OEM_COMMA, true},
                                            {VK_OEM_COMMA, false}, {VK_LWIN, false}, {'B', true},     {'B', false}};
const std::vector<TestKey> kKeyTestMac = {{VK_LWIN, true}, {VK_SPACE, true}, {VK_SPACE, false}, {VK_LWIN, false}};

bool inject_keys(const std::vector<TestKey>& seq) {
  // 自分のウィンドウにだけ送る。ほかのウィンドウではWin+Spaceで入力言語が切り替わる。
  if (GetForegroundWindow() != g_app.main) SetForegroundWindow(g_app.main);
  if (GetForegroundWindow() != g_app.main) return false;
  std::vector<INPUT> in;
  const DWORD t0 = GetTickCount();
  for (const TestKey& k : seq) {
    INPUT x{};
    x.type = INPUT_KEYBOARD;
    x.ki.wVk = k.vk;
    x.ki.wScan = static_cast<WORD>(MapVirtualKeyW(k.vk, MAPVK_VK_TO_VSC));
    x.ki.dwFlags = (k.down ? 0 : KEYEVENTF_KEYUP) | (k.vk == VK_LWIN ? KEYEVENTF_EXTENDEDKEY : 0);
    x.ki.time = t0 + static_cast<DWORD>(in.size());  // 実際のキーボードと同じく1 msずつずらす
    in.push_back(x);
  }
  return SendInput(static_cast<UINT>(in.size()), in.data(), sizeof(INPUT)) == in.size();
}

std::wstring session_status_text(const session::SessionStats& s, const session::SessionStats& prev, double dt) {
  const double fps = dt > 0 ? (s.frames_decoded - prev.frames_decoded) / dt : 0;
  const double mbps = dt > 0 ? (s.video_bytes - prev.video_bytes) * 8 / dt / 1e6 : 0;
  return std::format(L"{}  |  {}  |  {:.0f} fps  |  {:.1f} Mbit/s  |  損失 {}  |  破棄 {}  |  デコード: {}{}",
                     g_app.host_label, mode_label(), fps, mbps, s.lost_packets, s.dropped_frames, widen(s.decoder),
                     s.waiting_for_keyframe ? L"  |  キーフレーム待ち" : L"");
}

// --screenshot PATH.bmp。1枚目のディスプレイはそのパス、2枚目はPATH-2.bmpに保存する。
std::wstring screenshot_path(const std::wstring& path, int display) {
  if (display == 0) return path;
  const size_t dot = path.rfind(L'.');
  return dot == std::wstring::npos ? std::format(L"{}-{}", path, display + 1)
                                   : std::format(L"{}-{}{}", path.substr(0, dot), display + 1, path.substr(dot));
}

}  // namespace

int WINAPI wWinMain(HINSTANCE inst, HINSTANCE, PWSTR, int show) {
  g_app.inst = inst;
  INITCOMMONCONTROLSEX icc{sizeof(icc), ICC_BAR_CLASSES | ICC_STANDARD_CLASSES};
  InitCommonControlsEx(&icc);

  Args args = parse_args();
  if (args.log_file) open_log_file();
  std::vector<GpuInfo> gpus;
  try {
    gpus = enumerate_gpus();
  } catch (const std::exception& e) {
    log::error("GPU enumeration failed: {}", e.what());
  }
  if (args.list_gpus) {
    print_to_parent_console(L"Render / decode GPUs (DXGI) — use the index or a name substring with --gpu:\n" +
                            describe_gpus(gpus));
    return 0;
  }
  const bool interactive = args.smoke_seconds == 0;
  try {
    args.settings.gpu = pick_gpu(gpus, args.gpu_spec);
  } catch (const GpuSelectionError& e) {
    log::error("{}", e.what());
    if (interactive) MessageBoxW(nullptr, widen(e.what()).c_str(), L"iShareScreen", MB_ICONERROR);
    return 2;
  }

  const bool playing = !args.play_path.empty();
  // クリップの再生か、通常の（パターン描画の）スモークテストでなければセッションを張る。
  const bool want_session = !playing && (args.smoke_seconds == 0 || args.connect_now);
  if (playing) {
    args.settings.host = args.play_path;
  } else if (!want_session) {
    if (args.settings.host.empty()) args.settings.host = L"smoke-test";
  } else if (args.connect_now) {
    const int gpu = args.settings.gpu;
    load_saved_settings(args.settings, gpus);
    if (!args.gpu_spec.empty()) args.settings.gpu = gpu;
    auto pw = args.password_stdin ? read_stdin_password()
                                  : load_password(args.settings.host, args.settings.port, args.settings.user);
    if (!pw) {
      const std::wstring msg =
          args.password_stdin
              ? std::wstring(L"--password-stdin: 標準入力からパスワードを読めませんでした。")
              : std::format(L"{}@{}:{} のパスワードが保存されていません。一度ダイアログから「パスワードを保存する」を付けて接続してください。",
                            args.settings.user, args.settings.host, args.settings.port);
      log::error("{}", narrow(msg));
      if (interactive) MessageBoxW(nullptr, msg.c_str(), L"iShareScreen", MB_ICONERROR);
      return kExitNoCredentials;
    }
    args.settings.password = std::move(*pw);
  }

  // メインウィンドウは最初から作るが、接続するまで隠しておく。接続に失敗したときは
  // ビューアを出さない。隠れたビューのサイズとDPIでも、要求する解像度は決まる。
  if (!register_classes()) return 1;
  g_app.quality_bar = build_quality_menu();
  const Placement place = place_windows(1);
  g_app.main = CreateWindowExW(0, kMainClass, std::format(L"iShareScreen — {}", args.settings.host).c_str(),
                               WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN, place.main.left, place.main.top,
                               place.main.right - place.main.left, place.main.bottom - place.main.top, nullptr,
                               nullptr, inst, nullptr);
  primary().frame = g_app.main;
  g_app.status = CreateWindowExW(0, STATUSCLASSNAMEW, nullptr, WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP, 0, 0, 0, 0,
                                 g_app.main, nullptr, inst, nullptr);
  primary().view = CreateWindowExW(0, kViewClass, nullptr, WS_CHILD | WS_VISIBLE, 0, 0, 1, 1, g_app.main, nullptr,
                                   inst, nullptr);
  layout_children();
  add_fullscreen_menu_item(g_app.main);

  g_app.input = std::make_unique<input::InputMapper>(input::Sink{
      [](bool down, uint32_t keysym) {
        if (g_app.view_only) return;
        if (g_app.log_keys || g_app.log_input) log::info("key sent: {} 0x{:04x}", down ? "down" : "up", keysym);
        if (g_app.session_up) {
          g_app.session->send_key(down, keysym);
        } else {
          g_app.last_input = std::format(L"key 0x{:04x} {}", keysym, down ? L"down" : L"up");
        }
      },
      // Macのポインタ座標で受け取る（picture_to_host）。
      [](uint8_t buttons, int x, int y) {
        // 移動はボタンを押している間だけログに出す。すべての移動を出すと毎秒
        // 数百行になる。
        if (g_app.view_only) return;
        static uint8_t last_buttons = 0;
        if (g_app.log_input && (buttons || last_buttons)) log::info("pointer: buttons 0x{:02x} at {},{}", buttons, x, y);
        last_buttons = buttons;
        if (g_app.session_up) {
          g_app.session->send_pointer(buttons, x, y);
        } else {
          g_app.last_input = std::format(L"pointer ({}, {}) buttons=0x{:02x}", x, y, buttons);
        }
      }});
  g_app.log_keys = args.key_test;
  g_app.log_input = args.log_input;
  g_app.view_only = args.view_only;
  if (args.keyboard_grab && !args.view_only && !g_app.grab.start(g_app.main, primary().view, WM_APP_GRABBED_KEY)) {
    log::warn("keyboard grab unavailable: the Win key stays with Windows");
  }
  // 再生中はステータスバーにキーを表示するので、そこでもグラブする。
  g_app.grab.set_enabled(playing);
  WTSRegisterSessionNotification(g_app.main, NOTIFY_FOR_THIS_SESSION);

  FilePlayer player;
  if (!want_session) {
    if (args.fullscreen) toggle_fullscreen(primary());
    show_viewer(show, args.settings.gpu);
    if (primary().render_ok && !playing) {
      set_status(std::format(L"GPU: {}  |  描画の確認のみ (接続なし)", primary().renderer.adapter_name()));
    }
    if (playing && primary().render_ok) {
      try {
        player.start({args.play_path, args.settings.gpu, !args.software_decode, 30.0});
      } catch (const std::exception& e) {
        log::error("play: {}", e.what());
        set_status(L"再生できません: " + widen(e.what()));
      }
    }
  } else if (args.connect_now) {
    log::info("connect requested: {}:{} user={} gpu={}", narrow(args.settings.host), args.settings.port,
              narrow(args.settings.user), args.settings.gpu);
    configure_viewer(args);
    start_session(args, g_app.main);
  } else {
    // 接続中もダイアログは開いたままで、失敗したらダイアログ自身が受け取る。
    const bool connected =
        show_connect_dialog(inst, nullptr, gpus, args.settings, [&](const ConnectSettings& s, HWND dlg) {
          args.settings = s;
          log::info("connect requested: {}:{} user={} gpu={}", narrow(s.host), s.port, narrow(s.user), s.gpu);
          configure_viewer(args);
          start_session(args, dlg);
        });
    if (!connected) {
      // 接続中にキャンセルされた。接続は中断できない（下のWM_QUITを参照）。
      if (g_app.connecting) TerminateProcess(GetCurrentProcess(), 0);
      g_app.grab.stop();  // フックのスレッドが残るとプロセスが終わらない
      return 0;
    }
    PostMessageW(g_app.main, WM_APP_CONNECT_RESULT, 1, 0);
  }

  constexpr UINT_PTR kSmokeTimer = 1, kStatusTimer = 2, kResizeTestTimer = 4, kKeyTestTimer = 5;
  if (args.key_test && playing) SetTimer(g_app.main, kKeyTestTimer, 3000, nullptr);
  int resize_test_step = 0, key_test_step = 0;
  // セッションのスモークテスト用タイマーは、セッションが立ち上がってから始める。
  if (args.smoke_seconds > 0 && !want_session) {
    SetTimer(g_app.main, kSmokeTimer, static_cast<UINT>(args.smoke_seconds) * 1000, nullptr);
  }
  if (playing || want_session) SetTimer(g_app.main, kStatusTimer, 1000, nullptr);
  uint64_t frames = 0, uploads = 0, last_decoded = 0;
  uint64_t uploads_by_display[kMaxDisplays] = {};
  session::SessionStats prev_stats;
  auto prev_stats_t = std::chrono::steady_clock::now();
  // --perfのUI側（ms）。ピクチャの最後のパケットをソケットから読んでから、それを
  // 表示するPresentまで。それと、アップロードと描画ループの周期。
  PerfStat perf_latency, perf_upload, perf_loop;
  uint64_t perf_shown = 0;
  int perf_ticks = 0;
  SplitPictures perf_split;  // ウィンドウ1
  // --wake-test。新しい映像が来ていない秒数と、ポインタを動かしたかどうか。
  int wake_quiet_s = 0;
  bool wake_sent = false;
  std::chrono::steady_clock::time_point last_present{};
  std::vector<std::chrono::steady_clock::time_point> shown_received;

  MSG msg{};
  for (;;) {
    while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
      // 接続した（ダイアログ、または--connectのスレッドから）か、--connectで
      // 失敗した。
      if (msg.message == WM_APP_CONNECT_RESULT && msg.hwnd == g_app.main) {
        if (msg.wParam) {
          g_app.session_up = true;
          // Macのディスプレイが1枚のままのことがある（カーテンなし）。
          g_app.n_displays = std::min(g_app.n_displays, g_app.session->video_streams());
          show_viewer(show, args.settings.gpu);
          g_app.grab.set_enabled(true);
          set_status(std::format(L"{} に接続しました ({})。映像を待っています…", g_app.host_label, mode_label()));
          if (args.smoke_seconds > 0) {
            SetTimer(g_app.main, kSmokeTimer, static_cast<UINT>(args.smoke_seconds) * 1000, nullptr);
          }
          if (args.resize_test) SetTimer(g_app.main, kResizeTestTimer, 3000, nullptr);
          // ウィンドウに合わせた最初のリサイズが落ち着いてから。
          if (args.key_test) SetTimer(g_app.main, kKeyTestTimer, 6000, nullptr);
        } else {
          // 失敗した接続ではビューアを出さない。理由を表示して終わる。
          std::unique_ptr<std::wstring> why(reinterpret_cast<std::wstring*>(msg.lParam));
          g_app.exit_code = kExitSessionFailed;
          if (interactive) {
            MessageBoxW(nullptr, (L"接続できませんでした。\n\n" + *why).c_str(), L"iShareScreen", MB_ICONERROR);
          }
          DestroyWindow(g_app.main);
        }
        continue;
      }
      if (msg.message == WM_TIMER && msg.hwnd == g_app.main && msg.wParam == kSmokeTimer) {
        KillTimer(g_app.main, kSmokeTimer);
        log::info("smoke test: {} frames in {} s on \"{}\"", frames, args.smoke_seconds,
                  narrow(primary().renderer.adapter_name()));
        if (playing) {
          log::info("smoke test: decoded {} / uploaded {} video frames, decoder {}", player.frames_decoded(),
                    uploads, player.backend());
        }
        if (g_app.session) {
          const auto s = g_app.session->stats();
          log::info("smoke test: session decoded {} / uploaded {} frames ({}), {} packets, lost {}, dropped {}, "
                    "decoder {}",
                    s.frames_decoded, uploads,
                    g_app.n_displays > 1 ? std::format("{} + {} by display", uploads_by_display[0], uploads_by_display[1])
                                         : std::string("one display"),
                    s.video_packets, s.lost_packets, s.dropped_frames, s.decoder);
          for (int i = 0; i < g_app.n_displays; ++i) {
            if (uploads_by_display[i] == 0) g_app.exit_code = kExitSessionFailed;
          }
        }
        for (int i = 0; i < g_app.n_displays && !args.screenshot.empty(); ++i) {
          if (!g_app.displays[i].render_ok) continue;
          const std::wstring path = screenshot_path(args.screenshot, i);
          const bool saved = g_app.displays[i].renderer.save_bmp(path);
          log::info("screenshot {}: {}", narrow(path), saved ? "saved" : "failed");
        }
        if (args.key_test && g_app.session_up) {  // Cmd+Spaceで開いたものを閉じる
          g_app.session->send_key(true, 0xff1b);
          g_app.session->send_key(false, 0xff1b);
        }
        player.stop();
        DestroyWindow(g_app.main);
        continue;
      }
      if (msg.message == WM_TIMER && msg.hwnd == g_app.main && msg.wParam == kResizeTestTimer) {
        RECT wr{};
        GetWindowRect(g_app.main, &wr);
        const int w = wr.right - wr.left, h = wr.bottom - wr.top;
        const bool shrink = resize_test_step++ == 0;
        log::info("resize test: window {}x{} -> {}", w, h, shrink ? "80%" : "back");
        SetWindowPos(g_app.main, nullptr, 0, 0, shrink ? w * 4 / 5 : w * 5 / 4, shrink ? h * 4 / 5 : h * 5 / 4,
                     SWP_NOZORDER | SWP_NOMOVE | SWP_NOACTIVATE);
        if (resize_test_step == 1) {
          SetTimer(g_app.main, kResizeTestTimer, 6000, nullptr);
        } else {
          KillTimer(g_app.main, kResizeTestTimer);
        }
        continue;
      }
      if (msg.message == WM_TIMER && msg.hwnd == g_app.main && msg.wParam == kKeyTestTimer) {
        const bool burst = !g_app.session_up;
        const bool sent = burst ? inject_keys(kKeyTestBurst) : inject_keys({kKeyTestMac[key_test_step]});
        const bool done = burst || !sent || ++key_test_step == static_cast<int>(kKeyTestMac.size());
        if (!sent) log::info("key test: skipped, the viewer is not the foreground window");
        if (done) {
          KillTimer(g_app.main, kKeyTestTimer);
        } else {
          SetTimer(g_app.main, kKeyTestTimer, 100, nullptr);
        }
        continue;
      }
      if (msg.message == WM_TIMER && msg.hwnd == g_app.main && msg.wParam == kStatusTimer) {
        if (playing) {
          uint64_t d = player.frames_decoded();
          std::string err = player.error();
          set_status(err.empty() ? std::format(L"GPU: {}  |  デコード: {}  |  {} fps  |  入力: {}",
                                               primary().renderer.adapter_name(), widen(player.backend()),
                                               d - last_decoded, g_app.last_input.empty() ? L"-" : g_app.last_input)
                                 : L"再生エラー: " + widen(err));
          last_decoded = d;
        } else if (g_app.session_up) {
          const auto now = std::chrono::steady_clock::now();
          const auto s = g_app.session->stats();
          if (!g_app.session->alive()) {
            g_app.grab.set_enabled(false);
            set_status(L"切断されました: " + widen(g_app.session->failure()));
          } else {
            set_status(session_status_text(s, prev_stats, std::chrono::duration<double>(now - prev_stats_t).count()));
          }
          if (args.wake_test && !wake_sent) {
            wake_quiet_s = s.frames_decoded == prev_stats.frames_decoded ? wake_quiet_s + 1 : 0;
            if (wake_quiet_s >= 120) {
              const int cw = g_app.session->canvas_width(), ch = g_app.session->canvas_height();
              g_app.session->send_pointer(0, cw / 2 + 1, ch / 2);
              g_app.session->send_pointer(0, cw / 2, ch / 2);
              log::info("wake test: no picture for {} s; pointer nudged to wake the Mac", wake_quiet_s);
              wake_sent = true;
              SetTimer(g_app.main, kSmokeTimer, 30000, nullptr);
            }
          }
          prev_stats = s;
          prev_stats_t = now;
        }
        if (args.perf && g_app.session_up && ++perf_ticks % 5 == 0) {
          const auto [split, multi] = perf_split.take();
          log::info("perf ui: shown {:.1f}/s | {} | {} | {} | pictures of 2+ strips shown over 2+ presents {} of {}",
                    perf_shown / 5.0, PerfStat::summary("packet->screen ms", perf_latency.take()),
                    PerfStat::summary("upload ms", perf_upload.take()), PerfStat::summary("loop ms", perf_loop.take()),
                    split, multi);
          perf_shown = 0;
        }
        continue;
      }
      if (msg.message == WM_QUIT) {
        g_app.grab.stop();
        if (g_app.session_up) g_app.session->stop();
        // まだ進行中の接続は中断できない（Macでのクリックを待っていることがある）。
        // 接続が動いている最中に静的デストラクタを走らせないよう、そのまま終える。
        // ソケットはOSが閉じる。
        if (g_app.connecting) TerminateProcess(GetCurrentProcess(), static_cast<UINT>(g_app.exit_code));
        if (g_app.exit_code) return g_app.exit_code;  // 例: 接続に失敗し、レンダラーを作っていない
        return primary().render_ok ? static_cast<int>(msg.wParam) : 3;
      }
      TranslateMessage(&msg);
      DispatchMessageW(&msg);
    }
    bool any_visible = false;
    for (int i = 0; i < g_app.n_displays; ++i) {
      any_visible = any_visible || (g_app.displays[i].render_ok && !g_app.displays[i].minimized);
    }
    if (!any_visible) {
      WaitMessage();
      continue;
    }
    try {
      DisplayView& main_display = primary();
      if (auto f = player.take_frame()) {
        main_display.renderer.set_canvas(f->width, f->height);
        main_display.renderer.upload_tile(0, *f, f->height);
        ++uploads;
      }
      shown_received.clear();
      if (g_app.session_up) {
        if (args.input_test) {
          // キャンバスの中心の周りでポインタを毎秒2周させる（--legacy-cursorでは、
          // ウィンドウをドラッグしたときと同じくらいの映像が出る）。
          const int cw = g_app.session->canvas_width(), ch = g_app.session->canvas_height();
          const double a = std::chrono::duration<double>(std::chrono::steady_clock::now() - g_app.start).count() * 12.57;
          const int r = std::min(cw, ch) / 4;
          g_app.session->send_pointer(0, cw / 2 + static_cast<int>(r * std::cos(a)),
                                      ch / 2 + static_cast<int>(r * std::sin(a)));
        }
        const auto upload_start = std::chrono::steady_clock::now();
        if (g_app.session->standard_mode()) {
          g_app.session->take_fb_update(
              [&](const uint32_t* px, int w, int h, const std::vector<session::FbRect>& dirty) {
                for (const session::FbRect& d : dirty) main_display.renderer.upload_rgb(px, w, h, d.x, d.y, d.w, d.h);
                main_display.frame_w = w;
                main_display.frame_h = h;
                shown_received.push_back(upload_start);
                ++uploads;
                ++uploads_by_display[0];
              });
        } else {
          const std::vector<rfb::DisplayRect> rects = g_app.session->display_rects();
          follow_display_changes(rects);
          for (int i = 0; i < g_app.n_displays; ++i) {
            DisplayView& d = g_app.displays[i];
            const int stream = stream_for(i, rects);
            if (stream != d.stream) {
              log::info("window {} shows video stream {}{}", i + 1, stream,
                        i < static_cast<int>(rects.size()) ? std::format(" (display 0x{:x})", rects[i].display_id) : "");
              d.stream = stream;
            }
            for (const media::VideoFrame& f : g_app.session->take_frames(stream)) {
              if (!d.render_ok) continue;
              // HEVCのタイルは、このディスプレイのキャンバスを上から下へ積んだ
              // ストリップ（最後のストリップのパディング行は下端からはみ出す）。
              const int tiles = g_app.session->tiles();
              int canvas_h = f.height;
              if (tiles > 1) {
                canvas_h = i < static_cast<int>(rects.size()) ? rects[i].h : g_app.session->canvas_height();
                if (canvas_h <= 0 || canvas_h > f.height * tiles) canvas_h = f.height * tiles;
              }
              d.renderer.set_canvas(f.width, canvas_h);
              d.renderer.upload_tile(f.tile, f, f.height);
              d.frame_w = f.width;
              d.frame_h = canvas_h;
              display_frame_shown(d, f.width, f.height, tiles);
              if (i == 0) shown_received.push_back(f.received);
              if (i == 0 && args.perf && tiles > 1) perf_split.strip(f.rtp_ts, frames);
              ++uploads;
              ++uploads_by_display[i];
            }
          }
          if (g_app.arrange_pending && rects.size() >= 2) arrange_like_mac(rects);
        }
        if (args.perf && !shown_received.empty()) {
          perf_upload.add(std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - upload_start).count());
        }
        update_remote_cursor();
        track_view_size(args.settings);
      }
      const float t = std::chrono::duration<float>(std::chrono::steady_clock::now() - g_app.start).count();
      for (int i = 0; i < g_app.n_displays; ++i) {
        DisplayView& d = g_app.displays[i];
        if (!d.render_ok || d.minimized) continue;
        d.renderer.set_overlay(d.change.active() ? kDisplayChangeNotice : L"", GetDpiForWindow(d.view) / 96.0f);
        d.renderer.render(t);  // Present(1)がループをvsyncに合わせる
      }
      ++frames;
      if (args.perf) {
        const auto presented = std::chrono::steady_clock::now();
        if (last_present != std::chrono::steady_clock::time_point{}) {
          perf_loop.add(std::chrono::duration<double, std::milli>(presented - last_present).count());
        }
        last_present = presented;
        for (const auto& r : shown_received) {
          perf_latency.add(std::chrono::duration<double, std::milli>(presented - r).count());
          ++perf_shown;
        }
      }
    } catch (const std::exception& e) {
      log::error("render: {}", e.what());
      set_status(L"描画エラー: " + widen(e.what()));
      for (int i = 0; i < g_app.n_displays; ++i) g_app.displays[i].render_ok = false;
    }
  }
}
