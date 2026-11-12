#include "crypto/bigint.h"

#include <intrin.h>

#include <algorithm>
#include <stdexcept>

namespace iss::crypto {
namespace {

// t + a*b + carryを計算し、下位ワードを返して上位ワードをcarryに残す。
// (2^64-1)^2 + 2(2^64-1) = 2^128 - 1なので、オーバーフローしない。
inline uint64_t mac(uint64_t t, uint64_t a, uint64_t b, uint64_t& carry) {
  uint64_t hi;
  uint64_t lo = _umul128(a, b, &hi);
  unsigned char c = _addcarry_u64(0, lo, t, &lo);
  hi += c;
  c = _addcarry_u64(0, lo, carry, &lo);
  hi += c;
  carry = hi;
  return lo;
}

}  // namespace

BigUint BigUint::from_be(const uint8_t* p, size_t n) {
  BigUint r;
  r.limbs_.assign((n + 7) / 8, 0);
  for (size_t i = 0; i < n; ++i) {
    size_t bit_pos = (n - 1 - i) * 8;  // LSBから数えたバイトp[i]の位置
    r.limbs_[bit_pos / 64] |= uint64_t(p[i]) << (bit_pos % 64);
  }
  r.trim();
  return r;
}

Bytes BigUint::to_be(size_t len) const {
  if ((bit_length() + 7) / 8 > len) throw std::overflow_error("BigUint::to_be: value too large");
  Bytes out(len, 0);
  for (size_t i = 0; i < len; ++i) {
    size_t bit_pos = i * 8;
    size_t limb = bit_pos / 64;
    if (limb >= limbs_.size()) break;
    out[len - 1 - i] = uint8_t(limbs_[limb] >> (bit_pos % 64));
  }
  return out;
}

size_t BigUint::bit_length() const {
  if (limbs_.empty()) return 0;
  unsigned long idx;
  _BitScanReverse64(&idx, limbs_.back());
  return (limbs_.size() - 1) * 64 + idx + 1;
}

bool BigUint::bit(size_t i) const {
  size_t limb = i / 64;
  return limb < limbs_.size() && ((limbs_[limb] >> (i % 64)) & 1);
}

int compare(const BigUint& a, const BigUint& b) {
  if (a.limbs_.size() != b.limbs_.size()) return a.limbs_.size() < b.limbs_.size() ? -1 : 1;
  for (size_t i = a.limbs_.size(); i-- > 0;) {
    if (a.limbs_[i] != b.limbs_[i]) return a.limbs_[i] < b.limbs_[i] ? -1 : 1;
  }
  return 0;
}

BigUint operator+(const BigUint& a, const BigUint& b) {
  const auto& x = a.limbs_.size() >= b.limbs_.size() ? a.limbs_ : b.limbs_;
  const auto& y = a.limbs_.size() >= b.limbs_.size() ? b.limbs_ : a.limbs_;
  BigUint r;
  r.limbs_.resize(x.size() + 1);
  unsigned char c = 0;
  for (size_t i = 0; i < x.size(); ++i) {
    c = _addcarry_u64(c, x[i], i < y.size() ? y[i] : 0, &r.limbs_[i]);
  }
  r.limbs_[x.size()] = c;
  r.trim();
  return r;
}

BigUint operator-(const BigUint& a, const BigUint& b) {
  if (compare(a, b) < 0) throw std::underflow_error("BigUint: negative result");
  BigUint r;
  r.limbs_.resize(a.limbs_.size());
  unsigned char borrow = 0;
  for (size_t i = 0; i < a.limbs_.size(); ++i) {
    borrow = _subborrow_u64(borrow, a.limbs_[i], i < b.limbs_.size() ? b.limbs_[i] : 0, &r.limbs_[i]);
  }
  r.trim();
  return r;
}

BigUint operator*(const BigUint& a, const BigUint& b) {
  BigUint r;
  if (a.is_zero() || b.is_zero()) return r;
  r.limbs_.assign(a.limbs_.size() + b.limbs_.size(), 0);
  for (size_t i = 0; i < a.limbs_.size(); ++i) {
    uint64_t carry = 0;
    for (size_t j = 0; j < b.limbs_.size(); ++j) {
      r.limbs_[i + j] = mac(r.limbs_[i + j], a.limbs_[i], b.limbs_[j], carry);
    }
    r.limbs_[i + b.limbs_.size()] = carry;
  }
  r.trim();
  return r;
}

// 2進の筆算による割り算（シフトして引く）。O(bits(a) * limbs(m))で、SRPが作る
// 8192ビットの積でも数ミリ秒で済む。
BigUint operator%(const BigUint& a, const BigUint& m) {
  if (m.is_zero()) throw std::domain_error("BigUint: modulo by zero");
  if (compare(a, m) < 0) return a;
  const size_t n = m.limbs_.size();
  std::vector<uint64_t> r(n + 1, 0);
  for (size_t i = a.bit_length(); i-- > 0;) {
    // r = 2r + bit
    uint64_t carry_in = a.bit(i) ? 1 : 0;
    for (size_t k = 0; k <= n; ++k) {
      uint64_t next = r[k] >> 63;
      r[k] = (r[k] << 1) | carry_in;
      carry_in = next;
    }
    // r >= mならr -= m（r < 2mなので、引くのは1回で足りる）
    bool ge = r[n] != 0;
    if (!ge) {
      ge = true;
      for (size_t k = n; k-- > 0;) {
        if (r[k] != m.limbs_[k]) { ge = r[k] > m.limbs_[k]; break; }
      }
    }
    if (ge) {
      unsigned char borrow = 0;
      for (size_t k = 0; k < n; ++k) borrow = _subborrow_u64(borrow, r[k], m.limbs_[k], &r[k]);
      r[n] -= borrow;
    }
  }
  BigUint out;
  out.limbs_.assign(r.begin(), r.begin() + n);
  out.trim();
  return out;
}

BigUint mul_mod(const BigUint& a, const BigUint& b, const BigUint& m) { return (a * b) % m; }

BigUint mod_exp(const BigUint& base, const BigUint& exp, const BigUint& mod) {
  if (!mod.is_odd()) throw std::domain_error("mod_exp: modulus must be odd");
  const size_t n = mod.limbs_.size();
  const uint64_t* N = mod.limbs_.data();

  // n0inv = -N^-1 mod 2^64（ニュートン法。1回ごとに正しいビット数が倍になる）。
  uint64_t inv = 1;
  for (int i = 0; i < 6; ++i) inv *= 2 - N[0] * inv;
  const uint64_t n0inv = 0 - inv;

  // CIOS方式のMontgomery乗算。out = a*b*R^-1 mod N、R = 2^(64n)。
  std::vector<uint64_t> t(n + 2);
  auto mont_mul = [&](const std::vector<uint64_t>& a, const std::vector<uint64_t>& b,
                      std::vector<uint64_t>& out) {
    std::fill(t.begin(), t.end(), 0);
    for (size_t i = 0; i < n; ++i) {
      uint64_t carry = 0;
      for (size_t j = 0; j < n; ++j) t[j] = mac(t[j], a[j], b[i], carry);
      unsigned char c = _addcarry_u64(0, t[n], carry, &t[n]);
      t[n + 1] = c;

      uint64_t m = t[0] * n0inv;
      carry = 0;
      mac(t[0], m, N[0], carry);  // 計算の仕組み上、下位ワードは0になる
      for (size_t j = 1; j < n; ++j) t[j - 1] = mac(t[j], m, N[j], carry);
      c = _addcarry_u64(0, t[n], carry, &t[n - 1]);
      t[n] = t[n + 1] + c;
    }
    // 最後に条件付きで引く。結果は2N未満。
    bool ge = t[n] != 0;
    if (!ge) {
      ge = true;
      for (size_t k = n; k-- > 0;) {
        if (t[k] != N[k]) { ge = t[k] > N[k]; break; }
      }
    }
    if (ge) {
      unsigned char borrow = 0;
      for (size_t k = 0; k < n; ++k) borrow = _subborrow_u64(borrow, t[k], N[k], &out[k]);
    } else {
      std::copy(t.begin(), t.begin() + n, out.begin());
    }
  };

  auto to_mont = [&](const BigUint& x) {
    // x * R mod N。xを64nビット左にシフトしてから剰余を取って求める。
    BigUint shifted;
    BigUint xr = x % mod;
    shifted.limbs_.assign(n, 0);
    shifted.limbs_.insert(shifted.limbs_.end(), xr.limbs_.begin(), xr.limbs_.end());
    shifted.trim();
    BigUint r = shifted % mod;
    std::vector<uint64_t> v(n, 0);
    std::copy(r.limbs_.begin(), r.limbs_.end(), v.begin());
    return v;
  };

  std::vector<uint64_t> acc = to_mont(BigUint(1));
  std::vector<uint64_t> b = to_mont(base);
  std::vector<uint64_t> tmp(n);
  for (size_t i = exp.bit_length(); i-- > 0;) {
    mont_mul(acc, acc, tmp);
    acc.swap(tmp);
    if (exp.bit(i)) {
      mont_mul(acc, b, tmp);
      acc.swap(tmp);
    }
  }
  // Montgomery表現から戻す。ふつうの1を掛ける。
  std::vector<uint64_t> one(n, 0);
  one[0] = 1;
  mont_mul(acc, one, tmp);

  BigUint r;
  r.limbs_ = tmp;
  r.trim();
  return r;
}

}  // namespace iss::crypto
