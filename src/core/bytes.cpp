#include "core/bytes.h"

#include <windows.h>

namespace iss {

std::string to_hex(const uint8_t* p, size_t n) {
  static const char kDigits[] = "0123456789abcdef";
  std::string out(n * 2, '0');
  for (size_t i = 0; i < n; ++i) {
    out[2 * i] = kDigits[p[i] >> 4];
    out[2 * i + 1] = kDigits[p[i] & 0xf];
  }
  return out;
}

static int hex_nibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

Bytes from_hex(std::string_view hex) {
  if (hex.size() % 2) throw std::invalid_argument("from_hex: odd length");
  Bytes out(hex.size() / 2);
  for (size_t i = 0; i < out.size(); ++i) {
    int hi = hex_nibble(hex[2 * i]), lo = hex_nibble(hex[2 * i + 1]);
    if (hi < 0 || lo < 0) throw std::invalid_argument("from_hex: bad digit");
    out[i] = uint8_t((hi << 4) | lo);
  }
  return out;
}

void secure_wipe(void* p, size_t n) {
  if (p && n) SecureZeroMemory(p, n);
}

}  // namespace iss
