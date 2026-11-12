// 符号なしの多倍長整数。RFC 5054の4096ビットグループでSRP-6aを計算するのに
// 足りるだけの機能を持つ。add / sub / mul / modと、Montgomery法のmodexp。
// limbは64ビットで、リトルエンディアンに並べる（limb 0が最下位）。
#pragma once

#include <cstdint>
#include <vector>

#include "core/bytes.h"

namespace iss::crypto {

class BigUint {
 public:
  BigUint() = default;
  explicit BigUint(uint64_t v) { if (v) limbs_.push_back(v); }

  static BigUint from_be(const uint8_t* p, size_t n);
  static BigUint from_be(const Bytes& b) { return from_be(b.data(), b.size()); }
  // ビッグエンディアンで、`len` バイトになるよう左を0で埋める。収まらなければ例外を投げる。
  Bytes to_be(size_t len) const;

  bool is_zero() const { return limbs_.empty(); }
  bool is_odd() const { return !limbs_.empty() && (limbs_[0] & 1); }
  size_t bit_length() const;
  bool bit(size_t i) const;

  friend int compare(const BigUint& a, const BigUint& b);
  friend bool operator==(const BigUint& a, const BigUint& b) { return compare(a, b) == 0; }

  friend BigUint operator+(const BigUint& a, const BigUint& b);
  // a >= bであること。
  friend BigUint operator-(const BigUint& a, const BigUint& b);
  friend BigUint operator*(const BigUint& a, const BigUint& b);
  friend BigUint operator%(const BigUint& a, const BigUint& m);

  const std::vector<uint64_t>& limbs() const { return limbs_; }

 private:
  void trim() { while (!limbs_.empty() && limbs_.back() == 0) limbs_.pop_back(); }
  std::vector<uint64_t> limbs_;

  friend BigUint mod_exp(const BigUint& base, const BigUint& exp, const BigUint& mod);
};

// (a * b) mod m
BigUint mul_mod(const BigUint& a, const BigUint& b, const BigUint& m);
// base^exp mod m。Montgomery法を使うので、mは奇数でなければならない。
BigUint mod_exp(const BigUint& base, const BigUint& exp, const BigUint& mod);

}  // namespace iss::crypto
