// Win32の接続ダイアログ。接続先のMac（前に使ったものから選ぶか入力する）、
// パスワード、モード、映像コーデック、Macに伝える解像度、描画に使うGPU、
// カーテンを入力する。接続中もダイアログは開いたままなので、接続に失敗すると
// このダイアログに戻る。秘密でない項目はHKCU\Software\iShareScreen\iss-winに
// 保存する（Macの一覧はその下のHostsキー）。
#pragma once

#include <windows.h>

#include <functional>
#include <string>
#include <vector>

#include "app/renderer.h"

namespace iss::app {

struct ResolutionChoice {
  std::wstring label;
  int width;           // 0 = 手元のモニターに合わせる
  int height;
  double hidpi_scale;
};
const std::vector<ResolutionChoice>& resolution_choices();

// 高パフォーマンス（UDPでH.264。MacがApple siliconかつmacOS 14）か、
// 標準モードの画質レベルのどれか（TCPでフレームバッファ更新。Macは問わない）。
// レジストリにはインデックスを保存する。
struct ModeChoice {
  std::wstring label;    // ダイアログでの表示
  std::wstring name;     // 短い名前。ビューアのステータスバーと画質メニューで使う
  std::wstring quality;  // 空 = 高パフォーマンス。それ以外は--qualityの値
};
const std::vector<ModeChoice>& mode_choices();

// 高パフォーマンスモードの映像コーデック。HEVCならH.264の上限3840x2160を
// 7680x4320まで広げられる。レジストリにはインデックスを保存する。
struct CodecChoice {
  std::wstring label;
  bool hevc;     // --hevc / --hevc420
  bool hevc420;  // --gpuのGPUで4:2:0（D3D11VA）。falseならIntel Quick Syncで4:4:4
};
const std::vector<CodecChoice>& codec_choices();

struct ConnectSettings {
  std::wstring host;
  int port = 5900;
  std::wstring user;
  std::wstring password;  // ここには保存しない（app/credentials.hを参照）。使い終えたら消す
  int resolution = 0;     // resolution_choices()のインデックス
  int mode = 0;           // mode_choices()のインデックス
  int codec = 0;          // codec_choices()のインデックス
  int gpu = -1;          // DXGIアダプタのインデックス。-1 = 既定の高パフォーマンスGPU
  bool curtain = true;
  // Macに仮想ディスプレイを2枚作り、それぞれを別のウィンドウに出す
  // （高パフォーマンスかつカーテンありのときだけ）。
  bool two_displays = false;
};

// `s` の空の項目を、前回の接続で保存した値で埋める。
void load_saved_settings(ConnectSettings& s, const std::vector<GpuInfo>& gpus);
// セッション中に選んだ画質は、次の接続のモードにもする。
void save_mode(int mode);

// 接続処理が、接続を始めたウィンドウへ送るメッセージ。wParamは1で接続成功、
// 0で失敗（lParamは理由を入れたヒープ上のstd::wstring*。受け取った側でdeleteする）。
constexpr UINT WM_APP_CONNECT_RESULT = WM_APP + 1;

// `s`（パスワードを含む）で接続をバックグラウンドで始める。結果は
// WM_APP_CONNECT_RESULTとして `notify` に届く。
using ConnectFn = std::function<void(const ConnectSettings& s, HWND notify)>;

// モーダルダイアログを出す。接続ボタンで `connect` を呼び、ダイアログの中で
// 結果を待つ。失敗したらダイアログに表示し、入力はそのまま残してやり直せるようにする。
// 接続できたらtrue、キャンセルしたらfalseを返す（接続処理がまだ動いている
// こともある）。`io` の値を初期値にし（空の項目は保存した値で埋める）、
// 接続に使った値をパスワード抜きで `io` に返す。
bool show_connect_dialog(HINSTANCE inst, HWND parent, const std::vector<GpuInfo>& gpus, ConnectSettings& io,
                         const ConnectFn& connect);

}  // namespace iss::app
