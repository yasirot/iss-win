// 損失のあと、どのHEVCピクチャなら正しくデコードできるかを判定する
// （hevc_rps.pyと同じ役割だが、参照をたどって推移的に判定する）。ピクチャが
// 使う参照がすべて、DPBに残っている正常なピクチャなら、そのピクチャも正常とする。
// 失われたピクチャと、それを直接または別のピクチャ経由で参照するものは正常でない。
//
// Appleの4本のストリップは1つのシーケンスのピクチャだ。POCとDONLはストリップを
// またいで連番で、DPBは1つを共有し、各ストリップは自分のストリップの前のピクチャを
// 参照する（2026-10-09に計測）。そのため、ピクチャが失われてもおかしくなるのは
// そのストリップだけで、Macがそのストリップを更新するまでその状態が続く。
//
// パースするのは参照セットに必要な部分だけ。SPS（POCのビット数、short-termの
// セット、long-termのピクチャ）、PPS（スライスヘッダーの3つのフィールド）、
// それにスライスヘッダーのlong-term参照までを読む。
#pragma once

#include <cstdint>
#include <optional>
#include <set>
#include <vector>

#include "core/bytes.h"

namespace iss::media {

struct HevcStRps {
  std::vector<std::pair<int, bool>> s0, s1;  // (POCの差分, 現在のピクチャが使うか)
};

class HevcRefTracker {
 public:
  struct Picture {
    int poc = 0;
    bool idr = false;
    bool clean = false;
    std::vector<int> used;  // このピクチャが予測に使うPOC
  };

  // パラメータセット（2バイトのNALヘッダーを含む）。パースできないときはfalse。
  bool set_sps(const Bytes& nal);
  bool set_pps(const Bytes& nal);
  bool ready() const { return sps_ok_ && pps_ok_; }

  // 各ピクチャの最初のスライスセグメントをデコード順に渡す。POCの状態を進めて
  // ピクチャを記録し、正常なものは正常なピクチャの集合に加える。パースできない
  // とき（パラメータセットがない、最初のスライスでない）はnullopt。
  std::optional<Picture> add(const Bytes& slice_nal);
  // `add` が正常と判定したピクチャが、実際にはデコードできなかった。
  void mark_broken(int poc) { clean_.erase(poc); }
  void reset();

 private:
  bool sps_ok_ = false, pps_ok_ = false;
  int log2_poc_ = 4;
  int width_ = 0, height_ = 0, ctb_log2_ = 4;
  bool separate_colour_ = false;
  std::vector<HevcStRps> sets_;
  bool lt_present_ = false;
  std::vector<std::pair<int, bool>> lt_sps_;  // (POCのLSB, 使うか)
  bool dependent_slices_ = false, output_flag_ = false;
  int extra_bits_ = 0;

  int prev_msb_ = 0, prev_lsb_ = 0;
  bool seen_idr_ = false;
  std::set<int> clean_;
};

}  // namespace iss::media
