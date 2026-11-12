// --perf用の時間の計測値。報告の区間ごとに、件数、平均、95パーセンタイル、
// 最大を出す。スレッドセーフで、take()を呼ぶと新しい区間が始まる。
#pragma once

#include <algorithm>
#include <cmath>
#include <format>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

namespace iss {

class PerfStat {
 public:
  void add(double v) {
    std::lock_guard lk(mu_);
    v_.push_back(v);
  }

  std::vector<double> take() {
    std::lock_guard lk(mu_);
    return std::exchange(v_, {});
  }

  // "name mean/p95/max"（計測値がなければ"name -"）。
  static std::string summary(const char* name, std::vector<double> v) {
    if (v.empty()) return std::format("{} -", name);
    std::sort(v.begin(), v.end());
    double sum = 0;
    for (double x : v) sum += x;
    const double p95 = v[std::min(v.size() - 1, v.size() * 95 / 100)];
    return std::format("{} {:.1f}/{:.1f}/{:.1f}", name, sum / v.size(), p95, v.back());
  }

  // 間隔（ms）を `period_ms` の何周期分かで数える。"1:n 2:n 3:n 4+:n"。
  static std::string periods(const std::vector<double>& v, double period_ms) {
    size_t n[5] = {};
    for (double x : v) n[std::clamp(static_cast<int>(std::lround(x / period_ms)), 0, 4)]++;
    return std::format("0:{} 1:{} 2:{} 3:{} 4+:{}", n[0], n[1], n[2], n[3], n[4]);
  }

 private:
  std::mutex mu_;
  std::vector<double> v_;
};

}  // namespace iss
