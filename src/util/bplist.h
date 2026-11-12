// バイナリ形式のプロパティリスト（"bplist00"）。書き出す内容は、CPythonの
// plistlib.dumps(fmt=FMT_BINARY, sort_keys=True)とバイト単位で同じ（オブジェクトの順序、
// スカラーの重複除去、サイズの区分まで）。そのため、offerがPython版クライアントと一致する。
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "core/bytes.h"

namespace iss::plist {

struct Value {
  enum class Type { Null, Bool, Int, Real, String, Data, Array, Dict };
  Type type = Type::Null;
  bool b = false;
  int64_t i = 0;  // 2^63以上の整数はプロトコルで使わない
  double r = 0;
  std::string s;  // UTF-8
  Bytes data;
  std::vector<Value> array;
  std::vector<std::pair<std::string, Value>> dict;

  static Value integer(int64_t v) { Value x; x.type = Type::Int; x.i = v; return x; }
  static Value string(std::string v) { Value x; x.type = Type::String; x.s = std::move(v); return x; }
  static Value bytes(Bytes v) { Value x; x.type = Type::Data; x.data = std::move(v); return x; }
  static Value boolean(bool v) { Value x; x.type = Type::Bool; x.b = v; return x; }
  static Value make_dict() { Value x; x.type = Type::Dict; return x; }

  Value& set(std::string key, Value v) {
    dict.emplace_back(std::move(key), std::move(v));
    return *this;
  }
  const Value* get(std::string_view key) const;
};

Bytes write_binary(const Value& root);

// [p, p+n)をちょうど1つのbplistとしてパースする（トレーラーは末尾32バイトで
// なければならない）。構造に少しでも問題があればnullopt。
std::optional<Value> parse_binary(const uint8_t* p, size_t n);
inline std::optional<Value> parse_binary(const Bytes& b) { return parse_binary(b.data(), b.size()); }

}  // namespace iss::plist
