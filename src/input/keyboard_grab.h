// ビューアがキーボードを持っている間、Windowsキーをシェルに渡さないようにする。
// これでWinとWin+<key>は、スタートメニューを開いたりWin+C / Win+V / Win+Tab
// などを動かしたりせず、CmdとCmd+<key>としてMacに届く
// （frontend/desktop/keyboard_grab.pyのWin32部分の移植）。
//
// 低レベルキーボードフックが、Winキーと、Winを押している間に押したキーを
// すべて横取りする。ビューアはそれらをWM_KEYDOWNではなくtake()で受け取る。
// それ以外のキーは今までどおりWM_KEYDOWN / WM_CHARで届くので、キーボード配列も
// デッドキーもそのまま使える。WindowsからはWinが押されたように見えないので、
// ほかのキーはWindowsのホットキーを避けるための特別な扱いがいらない。
//
// Alt+SpaceのSpaceも横取りする。ウィンドウメニューやランチャー（Flow Launcher、
// PowerToys Runなど）に取られず、MacにOption+Spaceとして届く。Alt自体はWindowsに渡す。
//
// Win+LとCtrl+Alt+Delはフックでは止められず、Windowsはどうしてもロックする。
// Alt+Tabは、いつでも抜け出せるように手を付けない。
#pragma once

#include <windows.h>

#include <atomic>
#include <cstdint>
#include <mutex>
#include <thread>
#include <vector>

namespace iss::input {

// 横取りするかどうかの判定。テストできるようにフックから切り離してある。
class GrabFilter {
 public:
  // 低レベルのキーイベント1つ（VKは左右別のコード、時刻はKBDLLHOOKSTRUCTのもの）。
  // `active` はビューアがキーボードを持っているか。true = 横取りしてビューアに渡す。
  bool take(unsigned vk, bool down, bool active, DWORD time);
  // 離したことをフックが受け取れないままの押下中キーを忘れる（Win+Lの
  // ロック画面がキーアップを持っていってしまう）。
  void reset();

 private:
  bool win_taken() const { return taken_[VK_LWIN] || taken_[VK_RWIN]; }

  bool taken_[256] = {};   // 押下を横取りした。リピートと離すときも横取りする
  bool passed_[256] = {};  // 押下をWindowsに渡した。リピートと離すときも渡す
  DWORD last_[256] = {};   // そのキーの直近のイベントの時刻
};

struct GrabbedKey {
  unsigned vk = 0;
  unsigned scancode = 0;
  bool extended = false;
  bool down = false;
  DWORD time = 0;  // GetMessageTime()と同じクロック

  // このキーがWM_KEYDOWN / WM_KEYUPで届いていたら付いていたはずのlParam。
  intptr_t lparam() const {
    return 1 | (intptr_t(scancode & 0xFF) << 16) | (intptr_t(extended) << 24) | (intptr_t(!down) << 30) |
           (intptr_t(!down) << 31);
  }
};

class KeyboardGrab {
 public:
  KeyboardGrab() = default;
  KeyboardGrab(const KeyboardGrab&) = delete;
  KeyboardGrab& operator=(const KeyboardGrab&) = delete;
  ~KeyboardGrab() { stop(); }

  // 専用のスレッドからキーボードをフックする。低レベルフックは数百ms以内に
  // 応答しなければならず、UIスレッドはPresentやリサイズで止まっていることがあるためだ。
  // 横取りしたキーはキューに入れ、`view` に `notify` をポストする。
  // 横取りが働くのは、`main` が前面のウィンドウで、ビューがフォーカスを持ち、
  // set_enabled(true)が呼ばれているときだけ。
  bool start(HWND main, HWND view, UINT notify);
  void stop();
  // 2つ目のビューアウィンドウ（Macの2枚目のディスプレイ）。どちらかが前面に
  // ある間は横取りが働き、前面にある方のビューに `notify` をポストする。
  void add_window(HWND frame, HWND view) {
    view2_ = view;
    frame2_ = frame;
  }

  void set_enabled(bool on) { enabled_ = on; }
  void set_focused(bool on);
  // セッションがロックされた（Win+L）。フック側が覚えている押下中のキーを捨てる。
  void reset() { reset_ = true; }

  // 横取りしたキーを押された順に返す。
  std::vector<GrabbedKey> take();

 private:
  static LRESULT CALLBACK hook_proc(int code, WPARAM wp, LPARAM lp);
  bool on_event(const KBDLLHOOKSTRUCT& k, bool down);

  HWND main_ = nullptr, view_ = nullptr;
  std::atomic<HWND> frame2_{nullptr}, view2_{nullptr};
  UINT notify_ = 0;
  std::thread thread_;
  DWORD thread_id_ = 0;
  std::atomic<bool> enabled_{false}, focused_{false}, reset_{false};
  GrabFilter filter_;  // フックのスレッドからだけ触る
  std::mutex mu_;
  std::vector<GrabbedKey> queue_;
};

}  // namespace iss::input
