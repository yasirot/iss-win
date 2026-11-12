// ウィンドウとモニターの対応を決める。Win32を呼ばないので、テストから動かせる。
#pragma once

#include <vector>

namespace iss::app {

// 全画面にするウィンドウのモニターを優先順（全画面を指示したウィンドウが先頭）に
// 決める。`on[i]`はウィンドウiが今いるモニター（モニター一覧の添字、不明なら-1）。
// `taken`はモニターごとに1要素で、全画面のウィンドウが既にあるところがtrue。
// 各ウィンドウは自分のいるモニターを取り、取れなければ最初の空いているモニターを
// 取る。残りがなければ-1（そのウィンドウはウィンドウのまま）。
inline std::vector<int> fullscreen_monitors(const std::vector<int>& on, std::vector<bool> taken) {
  const int monitors = static_cast<int>(taken.size());
  std::vector<int> out;
  out.reserve(on.size());
  for (int m : on) {
    if (m < 0 || m >= monitors || taken[m]) {
      m = -1;
      for (int i = 0; i < monitors && m < 0; ++i) {
        if (!taken[i]) m = i;
      }
    }
    if (m >= 0) taken[m] = true;
    out.push_back(m);
  }
  return out;
}

// 全画面のウィンドウ2つについて、モニターの左右の並び（左端の座標）がMac上の
// ディスプレイの並び（バッキングキャンバスでのx）と逆ならtrue。逆だと、ポインタは
// Mac上でもう一方のディスプレイに接していない側の端からウィンドウを出てしまう。
inline bool monitors_against_mac_order(int monitor_left_a, int monitor_left_b, int mac_x_a, int mac_x_b) {
  if (monitor_left_a == monitor_left_b || mac_x_a == mac_x_b) return false;
  return (monitor_left_a < monitor_left_b) != (mac_x_a < mac_x_b);
}

}  // namespace iss::app
