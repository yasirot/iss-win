#include "input/input_mapper.h"

#include <windows.h>

#include <algorithm>
#include <cmath>

namespace iss::input {
namespace {

// AppleのサーバーはAlt_LをCmdにし、Alt_R / Meta_R / Super_Rには何も割り当てない
// （macOSで確認）。そのためAltは左右ともMeta_L（Option）、Winは左右ともSuper_L（Cmd）で送る。
constexpr uint32_t XK_Meta_L = 0xffe7;
constexpr uint32_t XK_Super_L = 0xffeb;
constexpr uint8_t BTN_LEFT = 1 << 0;
constexpr uint8_t BTN_RIGHT = 1 << 1;  // Appleではbit 1 = 右
constexpr uint8_t BTN_MIDDLE = 1 << 2;
constexpr uint8_t BTN_SCROLL_UP = 1 << 3;
constexpr uint8_t BTN_SCROLL_DOWN = 1 << 4;

bool extended(intptr_t lparam) { return (lparam >> 24) & 1; }
unsigned scancode(intptr_t lparam) { return static_cast<unsigned>((lparam >> 16) & 0xFF); }

// WM_KEYDOWNは左右のShift / Ctrl / Altを同じコードで報告するので、左右を分ける。
unsigned sided_vk(unsigned vk, bool ext, unsigned sc) {
  switch (vk) {
    case VK_SHIFT: return sc == 0x36 ? VK_RSHIFT : VK_LSHIFT;
    case VK_CONTROL: return ext ? VK_RCONTROL : VK_LCONTROL;
    case VK_MENU: return ext ? VK_RMENU : VK_LMENU;
    default: return vk;
  }
}

bool is_modifier(uint32_t keysym) { return keysym >= 0xffe1 && keysym <= 0xffee; }  // Shift_L .. Hyper_R

}  // namespace

uint32_t vk_to_keysym(unsigned vk, bool ext, unsigned sc) {
  switch (vk) {
    case VK_ESCAPE: return 0xff1b;
    case VK_TAB: return 0xff09;
    case VK_BACK: return 0xff08;
    case VK_RETURN: return 0xff0d;
    case VK_DELETE: return 0xffff;
    case VK_INSERT: return 0xff63;
    case VK_HOME: return 0xff50;
    case VK_END: return 0xff57;
    case VK_PRIOR: return 0xff55;
    case VK_NEXT: return 0xff56;
    case VK_LEFT: return 0xff51;
    case VK_UP: return 0xff52;
    case VK_RIGHT: return 0xff53;
    case VK_DOWN: return 0xff54;
    case VK_SHIFT: return sc == 0x36 ? 0xffe2 : 0xffe1;  // 右Shiftのscancodeは0x36
    case VK_LSHIFT: return 0xffe1;
    case VK_RSHIFT: return 0xffe2;
    case VK_CONTROL: return ext ? 0xffe4 : 0xffe3;
    case VK_LCONTROL: return 0xffe3;
    case VK_RCONTROL: return 0xffe4;
    case VK_MENU:
    case VK_LMENU:
    case VK_RMENU: return XK_Meta_L;
    case VK_LWIN:
    case VK_RWIN: return XK_Super_L;
    case VK_CAPITAL: return 0xffe5;
    default: break;
  }
  if (vk >= VK_F1 && vk <= VK_F12) return 0xffbe + (vk - VK_F1);
  // Spaceはわざと入れていない。WM_CHARで届くので、ここでも送ると毎回2回押した
  // ことになる（修飾キーを押しているときだけキーから作る）。
  return 0;
}

uint32_t shortcut_keysym(unsigned vk) {
  if (vk >= 'A' && vk <= 'Z') return 'a' + (vk - 'A');
  if (vk >= '0' && vk <= '9') return vk;
  if (vk >= VK_NUMPAD0 && vk <= VK_NUMPAD9) return '0' + (vk - VK_NUMPAD0);
  switch (vk) {
    case VK_SPACE: return ' ';
    case VK_MULTIPLY: return '*';
    case VK_ADD: return '+';
    case VK_SUBTRACT: return '-';
    case VK_DECIMAL: return '.';
    case VK_DIVIDE: return '/';
    default: break;
  }
  // 記号は配列ごとにキーが違う（JISの"@"はUSの"["）。bit 31はデッドキーの
  // 印だが、その場合も得られる文字をそのまま送ってよい。
  wchar_t c = LOWORD(MapVirtualKeyW(vk, MAPVK_VK_TO_CHAR));
  if (c < 0x20 || c == 0x7F) return 0;
  CharLowerBuffW(&c, 1);
  return c;
}

bool InputMapper::modifier_held() const {
  return (held_[VK_LCONTROL] || held_[VK_RCONTROL] || held_[VK_LMENU] || held_[VK_RMENU] || held_[VK_LWIN] ||
          held_[VK_RWIN]) &&
         !altgr_;
}

uint32_t InputMapper::keysym_for(unsigned vk, bool ext, unsigned sc) const {
  if (opt_.ctrl_as_cmd && (vk == VK_LCONTROL || vk == VK_RCONTROL)) return XK_Super_L;
  if (uint32_t keysym = vk_to_keysym(vk, ext, sc)) return keysym;
  return modifier_held() ? shortcut_keysym(vk) : 0;
}

void InputMapper::key_down(unsigned vk, intptr_t lparam) {
  const bool ext = extended(lparam);
  const unsigned sc = scancode(lparam);
  vk = sided_vk(vk, ext, sc);
  if (vk > 0xFF) return;
  // AltGrはLCtrl + RAltとして届き、その文字はWM_CHARで来る。そのため、
  // 修飾キーを押しているときの文字の合成をAltGrで動かしてはいけない。
  if (vk == VK_RMENU && (held_[VK_LCONTROL] || held_[VK_RCONTROL])) altgr_ = true;
  held_[vk] = true;
  if (altgr_ && vk == VK_RMENU) return;  // AltGrはOptionとして送らない
  const uint32_t keysym = keysym_for(vk, ext, sc);
  if (!keysym || !sink_.key) return;
  if (sent_[vk] == keysym && is_modifier(keysym)) return;  // 押したままの修飾キーのオートリピート
  if (sent_[vk] && sent_[vk] != keysym) sink_.key(false, sent_[vk]);
  sent_[vk] = keysym;
  sink_.key(true, keysym);
}

void InputMapper::key_up(unsigned vk, intptr_t lparam) {
  const bool ext = extended(lparam);
  vk = sided_vk(vk, ext, scancode(lparam));
  if (vk > 0xFF) return;
  held_[vk] = false;
  if (vk == VK_LMENU || vk == VK_RMENU) altgr_ = false;
  const uint32_t keysym = sent_[vk];
  sent_[vk] = 0;
  if (keysym && sink_.key) sink_.key(false, keysym);
}

void InputMapper::char_input(wchar_t unit) {
  if (unit >= 0xD800 && unit <= 0xDBFF) {  // 上位サロゲート。対になる下位を待つ
    high_surrogate_ = unit;
    return;
  }
  uint32_t cp = unit;
  if (unit >= 0xDC00 && unit <= 0xDFFF) {
    if (!high_surrogate_) return;
    cp = 0x10000 + ((uint32_t(high_surrogate_) - 0xD800) << 10) + (uint32_t(unit) - 0xDC00);
  }
  high_surrogate_ = 0;
  // 制御文字（Enter、Tab、Backspace、Esc、Ctrl+英字のコード）は
  // WM_KEYDOWNの側で送り済み。
  if (cp < 0x20 || cp == 0x7F) return;
  if (modifier_held() || !sink_.key) return;  // この場合はキーから作って送る
  // Pythonクライアントと同じく、コードポイントをそのままkeysymにする。
  sink_.key(true, cp);
  sink_.key(false, cp);
}

void InputMapper::release_all() {
  // 先に普通のキーを離し、そのあと一緒に押していた修飾キーを離す。
  for (int pass = 0; pass < 2; ++pass) {
    for (uint32_t& keysym : sent_) {
      if (keysym && is_modifier(keysym) == (pass == 1)) {
        if (sink_.key) sink_.key(false, keysym);
        keysym = 0;
      }
    }
  }
  std::fill(std::begin(held_), std::end(held_), false);
  altgr_ = false;
  if (buttons_ && have_pos_ && sink_.pointer) {
    buttons_ = 0;
    sink_.pointer(0, x_, y_);
  }
}

void InputMapper::move(int x, int y) {
  x_ = x;
  y_ = y;
  have_pos_ = true;
  if (sink_.pointer) sink_.pointer(buttons_, x, y);
}

void InputMapper::button(int which, bool down) {
  uint8_t bit = which == 0 ? BTN_LEFT : which == 1 ? BTN_RIGHT : which == 2 ? BTN_MIDDLE : 0;
  if (!bit) return;
  buttons_ = down ? uint8_t(buttons_ | bit) : uint8_t(buttons_ & ~bit);
  if (have_pos_ && sink_.pointer) sink_.pointer(buttons_, x_, y_);
}

void InputMapper::wheel(double notches, double now_ms) {
  if (!have_pos_ || notches == 0 || !sink_.pointer) return;
  // macOSは速く続くホイールイベントを加速する。RFBでは加速なしの刻みしか
  // 送れないので、ここで加速の曲線を再現する（値はPythonクライアントから）。
  const double dt = now_ms - wheel_last_ms_;
  wheel_last_ms_ = now_ms;
  const double accel = dt < 25 ? 10.0 : dt < 50 ? 6.0 : dt < 100 ? 3.5 : dt < 200 ? 2.0 : dt < 350 ? 1.4 : 1.0;
  // ノッチが正 = 上スクロール = 送るdyは負。
  wheel_accum_ += -notches * opt_.wheel_mult * accel;
  wheel_accum_ = std::clamp(wheel_accum_, -200.0, 200.0);
  const int ticks = static_cast<int>(wheel_accum_);  // 0方向に切り捨て、端数は残す
  if (ticks == 0) return;
  const int emit = std::clamp(ticks, -50, 50);
  wheel_accum_ -= emit;
  const uint8_t bit = emit < 0 ? BTN_SCROLL_UP : BTN_SCROLL_DOWN;
  for (int i = 0; i < std::abs(emit); ++i) {
    sink_.pointer(bit, x_, y_);
    sink_.pointer(0, x_, y_);
  }
}

}  // namespace iss::input
