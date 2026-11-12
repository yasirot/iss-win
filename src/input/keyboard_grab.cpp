#include "input/keyboard_grab.h"

#include <algorithm>
#include <future>
#include <utility>

#include "core/log.h"

namespace iss::input {
namespace {

// オートリピートの開始までの遅れ（最大1秒）や間隔（約0.4秒）より長い。押したままと
// 見ているキーがこれ以上あとにまた押されたら、離したのを取りこぼした新しい押下とみなす。
constexpr DWORD kRepeatGapMs = 1500;

// 低レベルフックにはユーザーデータを渡せないので、横取りはプロセスに1つだけ置く。
KeyboardGrab* g_grab = nullptr;

}  // namespace

bool GrabFilter::take(unsigned vk, bool down, bool active, DWORD time) {
  if (vk > 0xFF) return false;
  const bool stale = time - last_[vk] > kRepeatGapMs;
  last_[vk] = time;
  if (!down) {
    const bool taken = taken_[vk];
    taken_[vk] = passed_[vk] = false;
    return taken;
  }
  if (!stale) {  // オートリピート。押下を送った先へ送る
    if (taken_[vk]) return true;
    if (passed_[vk]) return false;
  }
  const bool alt_space = vk == VK_SPACE && (passed_[VK_LMENU] || passed_[VK_RMENU]);
  const bool take = active && (vk == VK_LWIN || vk == VK_RWIN || win_taken() || alt_space);
  taken_[vk] = take;
  passed_[vk] = !take;
  return take;
}

void GrabFilter::reset() {
  std::fill(std::begin(taken_), std::end(taken_), false);
  std::fill(std::begin(passed_), std::end(passed_), false);
}

bool KeyboardGrab::start(HWND main, HWND view, UINT notify) {
  if (thread_.joinable()) return true;
  main_ = main;
  view_ = view;
  notify_ = notify;
  g_grab = this;
  std::promise<bool> hooked;
  std::future<bool> result = hooked.get_future();
  thread_ = std::thread([this, &hooked] {
    MSG msg;
    PeekMessageW(&msg, nullptr, WM_USER, WM_USER, PM_NOREMOVE);  // stop()のWM_QUIT用のキュー
    thread_id_ = GetCurrentThreadId();
    HHOOK hook = SetWindowsHookExW(WH_KEYBOARD_LL, hook_proc, GetModuleHandleW(nullptr), 0);
    if (!hook) log::warn("keyboard grab: SetWindowsHookEx failed ({})", GetLastError());
    hooked.set_value(hook != nullptr);
    if (!hook) return;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
    }
    UnhookWindowsHookEx(hook);
  });
  if (result.get()) return true;
  thread_.join();
  g_grab = nullptr;
  return false;
}

void KeyboardGrab::stop() {
  if (!thread_.joinable()) return;
  PostThreadMessageW(thread_id_, WM_QUIT, 0, 0);
  thread_.join();
  g_grab = nullptr;
}

void KeyboardGrab::set_focused(bool on) {
  focused_ = on;
  if (on) reset_ = true;  // 一度ほかをクリックして戻れば、押されたままのキーが消える
}

std::vector<GrabbedKey> KeyboardGrab::take() {
  std::lock_guard lk(mu_);
  return std::exchange(queue_, {});
}

LRESULT CALLBACK KeyboardGrab::hook_proc(int code, WPARAM wp, LPARAM lp) {
  if (code == HC_ACTION && g_grab) {
    const auto& k = *reinterpret_cast<const KBDLLHOOKSTRUCT*>(lp);
    if (g_grab->on_event(k, wp == WM_KEYDOWN || wp == WM_SYSKEYDOWN)) return 1;
  }
  return CallNextHookEx(nullptr, code, wp, lp);
}

bool KeyboardGrab::on_event(const KBDLLHOOKSTRUCT& k, bool down) {
  if (reset_.exchange(false)) filter_.reset();
  const HWND fg = GetForegroundWindow();
  const HWND frame2 = frame2_;
  const bool active = enabled_ && focused_ && (fg == main_ || (frame2 && fg == frame2));
  if (!filter_.take(k.vkCode, down, active, k.time)) return false;
  {
    std::lock_guard lk(mu_);
    queue_.push_back({k.vkCode, k.scanCode, (k.flags & LLKHF_EXTENDED) != 0, down, k.time});
  }
  PostMessageW(frame2 && fg == frame2 ? view2_.load() : view_, notify_, 0, 0);
  return true;
}

}  // namespace iss::input
