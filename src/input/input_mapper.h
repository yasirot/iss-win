// Win32のキーボードとマウス → RFBのキーイベントとポインタイベント
// （frontend/desktop/app.pyとkeymap.pyの入力コールバックの移植）。
//
// キーはX11のkeysymで送る。特殊キー（矢印、Fキー、修飾キーなど）は
// WM_KEYDOWN/UPから、印字できる文字はWM_CHARから取り、ユーザーの
// キーボード配列（JIS、AZERTY、Shift、AltGrなど）をそのまま反映する。
// Ctrl/Alt/Winを押している間はWindowsが使えるWM_CHARを送ってこないので、
// Shiftなしでそのキーが打つ文字（今の配列での文字）をキーから作る。
// MacはCmd+Shift+/を、ShiftとCmdを押した状態の"/"として受け取るためだ。
//
// 押したと伝えたキーは、ショートカットにしていた修飾キーが先に離されても、
// 押したときと同じkeysymで離す。
//
// マウスはAppleのボタンマスク（bit 1 = 右、bit 2 = 中）を使う。ホイールは
// bit 3/4の押す・離すの組にし、スクロール1ピクセルごとに1組送る。
// 速度の曲線はPythonクライアントに合わせる。
#pragma once

#include <cstdint>
#include <functional>

namespace iss::input {

struct Sink {
  std::function<void(bool down, uint32_t keysym)> key;
  std::function<void(uint8_t buttons, int x, int y)> pointer;
};

// 印字できないWin32仮想キーに対応するX11のkeysym。なければ0。`extended` は
// WM_KEYDOWNのlParamのbit 24で、右と左のCtrlを見分ける。
// `scancode`（bit 16-23）で右と左のShiftを見分ける。
uint32_t vk_to_keysym(unsigned vk, bool extended, unsigned scancode);

// 今のキーボード配列でそのキーがShiftなしで打つ文字を小文字にしたもの。
// なければ0。ショートカットではこの文字を送る。
uint32_t shortcut_keysym(unsigned vk);

class InputMapper {
 public:
  struct Options {
    bool ctrl_as_cmd = false;  // CtrlをMacのCmd（Super）として送る
    double wheel_mult = 12.0;  // ホイール1ノッチあたりのスクロール量（加速前、ピクセル）
  };

  InputMapper(Sink sink, Options opt) : sink_(std::move(sink)), opt_(opt) {}
  explicit InputMapper(Sink sink) : InputMapper(std::move(sink), Options{}) {}

  // キーボード。`lparam` はWM_KEYDOWN/UPのlParamそのもの（使うのはscancodeと
  // extendedのビットだけ）。左右共通のVK_SHIFT / VK_CONTROL / VK_MENUも、
  // 低レベルフックが渡す左右別のコードも受け付ける。
  void key_down(unsigned vk, intptr_t lparam);
  void key_up(unsigned vk, intptr_t lparam);
  // WM_CHAR（UTF-16の1単位。サロゲートペアはつなげる）。
  void char_input(wchar_t unit);
  // 押したと伝えたキーをすべて離す（フォーカスを失ったとき）。ホスト側で
  // 修飾キーが押されたままにならないようにするため。
  void release_all();

  // マウス。座標はキャンバス（ホスト）のピクセル座標。
  void move(int x, int y);
  void button(int which, bool down);  // 0 = 左、1 = 右、2 = 中
  // ノッチ単位のホイール量（WM_MOUSEWHEELのdelta / 120。高分解能ホイールでは
  // 小数になる）。正 = ユーザーから離れる向き（上スクロール）。
  // `now_ms` はミリ秒単位の単調増加クロック。
  void wheel(double notches, double now_ms);

  uint8_t buttons() const { return buttons_; }

 private:
  uint32_t keysym_for(unsigned vk, bool ext, unsigned scancode) const;
  bool modifier_held() const;

  Sink sink_;
  Options opt_;
  uint8_t buttons_ = 0;
  int x_ = 0, y_ = 0;
  bool have_pos_ = false;
  double wheel_accum_ = 0;
  double wheel_last_ms_ = -1e9;
  wchar_t high_surrogate_ = 0;
  // （左右別の）仮想キーごとに、手元で押されているかと、キーを離すまでの間
  // ホストに押したと伝えたkeysym（0 = なし）を持つ。
  bool held_[256] = {};
  uint32_t sent_[256] = {};
  bool altgr_ = false;
};

}  // namespace iss::input
