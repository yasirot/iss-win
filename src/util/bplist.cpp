#include "util/bplist.h"

#include <windows.h>

#include <algorithm>
#include <cstring>
#include <map>

namespace iss::plist {

const Value* Value::get(std::string_view key) const {
  for (const auto& [k, v] : dict) {
    if (k == key) return &v;
  }
  return nullptr;
}

namespace {

int count_to_size(uint64_t count) {
  if (count < (1ull << 8)) return 1;
  if (count < (1ull << 16)) return 2;
  if (count < (1ull << 32)) return 4;
  return 8;
}

bool is_scalar(const Value& v) { return v.type != Value::Type::Array && v.type != Value::Type::Dict; }

// plistlibの重複除去テーブル（キーは(type(value), value)）に相当するキー。
std::string scalar_key(const Value& v) {
  using T = Value::Type;
  switch (v.type) {
    case T::Null: return "n";
    case T::Bool: return v.b ? "b1" : "b0";
    case T::Int: return "i" + std::to_string(v.i);
    case T::Real: { std::string k = "r"; k.append(reinterpret_cast<const char*>(&v.r), sizeof(double)); return k; }
    case T::String: return "s" + v.s;
    case T::Data: return "d" + std::string(v.data.begin(), v.data.end());
    default: return {};
  }
}

std::vector<std::pair<std::string, const Value*>> sorted_items(const Value& d) {
  std::vector<std::pair<std::string, const Value*>> items;
  for (const auto& [k, v] : d.dict) items.emplace_back(k, &v);
  // UTF-8のバイト順 == コードポイント順 == Pythonのstrの並び順。
  std::stable_sort(items.begin(), items.end(), [](const auto& a, const auto& b) { return a.first < b.first; });
  return items;
}

std::wstring utf8_to_utf16(const std::string& s) {
  if (s.empty()) return {};
  int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
  std::wstring w(n, L'\0');
  MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), w.data(), n);
  return w;
}

std::string utf16_to_utf8(const std::wstring& w) {
  if (w.empty()) return {};
  int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
  std::string s(n, '\0');
  WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), s.data(), n, nullptr, nullptr);
  return s;
}

class Writer {
 public:
  Bytes write(const Value& root) {
    flatten(root);
    ref_size_ = count_to_size(objects_.size());
    out_.str("bplist00");
    offsets_.assign(objects_.size(), 0);
    for (size_t i = 0; i < objects_.size(); ++i) write_object(i);
    uint64_t table_off = out_.size();
    int off_size = count_to_size(table_off);
    for (uint64_t o : offsets_) put_sized(o, off_size);
    out_.zeros(5).u8(0).u8(static_cast<uint8_t>(off_size)).u8(static_cast<uint8_t>(ref_size_));
    out_.be64(objects_.size()).be64(refnum(root)).be64(table_off);
    return out_.take();
  }

 private:
  void flatten(const Value& v) {
    if (is_scalar(v)) {
      if (scalar_refs_.count(scalar_key(v))) return;
      scalar_refs_[scalar_key(v)] = objects_.size();
    } else {
      if (container_refs_.count(&v)) return;
      container_refs_[&v] = objects_.size();
    }
    objects_.push_back(&v);
    if (v.type == Value::Type::Dict) {
      // Pythonと同じく、キーを先に、次に値を平らに並べる。
      auto items = sorted_items(v);
      for (auto& [k, val] : items) flatten_key(k);
      for (auto& [k, val] : items) flatten(*val);
    } else if (v.type == Value::Type::Array) {
      for (const auto& e : v.array) flatten(e);
    }
  }

  void flatten_key(const std::string& k) {
    std::string key = "s" + k;
    if (scalar_refs_.count(key)) return;
    scalar_refs_[key] = objects_.size();
    key_storage_.push_back(Value::string(k));
    objects_.push_back(nullptr);  // あとで補う。キーの値はkey_storage_に置く
    key_slots_.push_back(objects_.size() - 1);
  }

  uint64_t refnum(const Value& v) const {
    if (is_scalar(v)) return scalar_refs_.at(scalar_key(v));
    return container_refs_.at(&v);
  }
  uint64_t key_refnum(const std::string& k) const { return scalar_refs_.at("s" + k); }

  void put_sized(uint64_t v, int size) {
    switch (size) {
      case 1: out_.u8(static_cast<uint8_t>(v)); break;
      case 2: out_.be16(static_cast<uint16_t>(v)); break;
      case 4: out_.be32(static_cast<uint32_t>(v)); break;
      default: out_.be64(v); break;
    }
  }

  void write_size(uint8_t token, uint64_t size) {
    if (size < 15) {
      out_.u8(static_cast<uint8_t>(token | size));
    } else if (size < (1ull << 8)) {
      out_.u8(token | 0xF).u8(0x10).u8(static_cast<uint8_t>(size));
    } else if (size < (1ull << 16)) {
      out_.u8(token | 0xF).u8(0x11).be16(static_cast<uint16_t>(size));
    } else if (size < (1ull << 32)) {
      out_.u8(token | 0xF).u8(0x12).be32(static_cast<uint32_t>(size));
    } else {
      out_.u8(token | 0xF).u8(0x13).be64(size);
    }
  }

  void write_string(const std::string& s) {
    bool ascii = std::all_of(s.begin(), s.end(), [](char c) { return static_cast<unsigned char>(c) < 0x80; });
    if (ascii) {
      write_size(0x50, s.size());
      out_.str(s);
    } else {
      std::wstring w = utf8_to_utf16(s);
      write_size(0x60, w.size());
      for (wchar_t c : w) out_.be16(static_cast<uint16_t>(c));
    }
  }

  void write_object(size_t idx) {
    offsets_[idx] = out_.size();
    const Value* v = objects_[idx];
    if (!v) {  // dictのキー
      auto it = std::find(key_slots_.begin(), key_slots_.end(), idx);
      write_string(key_storage_[static_cast<size_t>(it - key_slots_.begin())].s);
      return;
    }
    using T = Value::Type;
    switch (v->type) {
      case T::Null: out_.u8(0x00); break;
      case T::Bool: out_.u8(v->b ? 0x09 : 0x08); break;
      case T::Int: {
        int64_t x = v->i;
        if (x < 0) out_.u8(0x13).be64(static_cast<uint64_t>(x));
        else if (x < (1ll << 8)) out_.u8(0x10).u8(static_cast<uint8_t>(x));
        else if (x < (1ll << 16)) out_.u8(0x11).be16(static_cast<uint16_t>(x));
        else if (x < (1ll << 32)) out_.u8(0x12).be32(static_cast<uint32_t>(x));
        else out_.u8(0x13).be64(static_cast<uint64_t>(x));
        break;
      }
      case T::Real: out_.u8(0x23).f64be(v->r); break;
      case T::Data: write_size(0x40, v->data.size()); out_.bytes(v->data); break;
      case T::String: write_string(v->s); break;
      case T::Array:
        write_size(0xA0, v->array.size());
        for (const auto& e : v->array) put_sized(refnum(e), ref_size_);
        break;
      case T::Dict: {
        auto items = sorted_items(*v);
        write_size(0xD0, items.size());
        for (auto& [k, val] : items) put_sized(key_refnum(k), ref_size_);
        for (auto& [k, val] : items) put_sized(refnum(*val), ref_size_);
        break;
      }
    }
  }

  ByteWriter out_;
  std::vector<const Value*> objects_;
  std::vector<uint64_t> offsets_;
  std::map<std::string, uint64_t> scalar_refs_;
  std::map<const Value*, uint64_t> container_refs_;
  std::vector<Value> key_storage_;
  std::vector<size_t> key_slots_;
  int ref_size_ = 1;
};

class Reader {
 public:
  Reader(const uint8_t* p, size_t n) : p_(p), n_(n) {}

  std::optional<Value> parse() {
    if (n_ < 8 + 32 || std::memcmp(p_, "bplist00", 8) != 0) return std::nullopt;
    const uint8_t* t = p_ + n_ - 32;
    off_size_ = t[6];
    ref_size_ = t[7];
    num_objects_ = rd_be64(t + 8);
    uint64_t top = rd_be64(t + 16);
    table_off_ = rd_be64(t + 24);
    auto valid_size = [](int s) { return s == 1 || s == 2 || s == 4 || s == 8; };
    if (!valid_size(off_size_) || !valid_size(ref_size_)) return std::nullopt;
    if (num_objects_ == 0 || top >= num_objects_ || table_off_ < 8) return std::nullopt;
    if (num_objects_ > (n_ - 32) / static_cast<uint64_t>(off_size_)) return std::nullopt;
    if (table_off_ + num_objects_ * off_size_ > n_ - 32) return std::nullopt;
    Value out;
    if (!read_object(top, out, 0)) return std::nullopt;
    return out;
  }

 private:
  bool sized(uint64_t pos, int size, uint64_t& v) const {
    if (pos + size > n_ - 32) return false;
    v = 0;
    for (int i = 0; i < size; ++i) v = (v << 8) | p_[pos + i];
    return true;
  }

  bool read_len(uint64_t& pos, uint8_t low, uint64_t& len) const {
    if (low != 0xF) { len = low; return true; }
    if (pos >= n_ - 32) return false;
    uint8_t m = p_[pos++];
    if ((m & 0xF0) != 0x10) return false;
    int size = 1 << (m & 0x0F);
    if (size > 8 || !sized(pos, size, len)) return false;
    pos += size;
    return true;
  }

  bool read_object(uint64_t ref, Value& out, int depth) {
    if (depth > 32 || ref >= num_objects_) return false;
    uint64_t pos;
    if (!sized(table_off_ + ref * off_size_, off_size_, pos) || pos < 8 || pos >= n_ - 32) return false;
    uint8_t marker = p_[pos++];
    uint8_t hi = marker >> 4, lo = marker & 0x0F;
    using T = Value::Type;
    switch (hi) {
      case 0x0:
        if (marker == 0x00) { out.type = T::Null; return true; }
        if (marker == 0x08 || marker == 0x09) { out.type = T::Bool; out.b = marker == 0x09; return true; }
        return false;
      case 0x1: {
        int size = 1 << lo;
        if (size > 8) return false;  // 16バイトの整数は扱わない
        uint64_t v;
        if (!sized(pos, size, v)) return false;
        out.type = T::Int;
        out.i = static_cast<int64_t>(v);
        return true;
      }
      case 0x2: {
        int size = 1 << lo;
        uint64_t v;
        if ((size != 4 && size != 8) || !sized(pos, size, v)) return false;
        out.type = T::Real;
        if (size == 4) { uint32_t u = static_cast<uint32_t>(v); float f; std::memcpy(&f, &u, 4); out.r = f; }
        else std::memcpy(&out.r, &v, 8);
        return true;
      }
      case 0x4: case 0x5: case 0x6: {
        uint64_t len;
        if (!read_len(pos, lo, len)) return false;
        uint64_t bytes = hi == 0x6 ? len * 2 : len;
        if (bytes > n_ - 32 || pos + bytes > n_ - 32) return false;
        if (hi == 0x4) { out.type = T::Data; out.data.assign(p_ + pos, p_ + pos + bytes); }
        else if (hi == 0x5) { out.type = T::String; out.s.assign(reinterpret_cast<const char*>(p_ + pos), bytes); }
        else {
          std::wstring w(len, L'\0');
          for (uint64_t i = 0; i < len; ++i) w[i] = static_cast<wchar_t>(rd_be16(p_ + pos + 2 * i));
          out.type = T::String;
          out.s = utf16_to_utf8(w);
        }
        return true;
      }
      case 0xA: case 0xD: {
        uint64_t count;
        if (!read_len(pos, lo, count)) return false;
        uint64_t refs = hi == 0xD ? count * 2 : count;
        if (refs > n_ || pos + refs * ref_size_ > n_ - 32) return false;
        if (hi == 0xA) {
          out.type = T::Array;
          for (uint64_t i = 0; i < count; ++i) {
            uint64_t r;
            sized(pos + i * ref_size_, ref_size_, r);
            Value e;
            if (!read_object(r, e, depth + 1)) return false;
            out.array.push_back(std::move(e));
          }
        } else {
          out.type = T::Dict;
          for (uint64_t i = 0; i < count; ++i) {
            uint64_t kr, vr;
            sized(pos + i * ref_size_, ref_size_, kr);
            sized(pos + (count + i) * ref_size_, ref_size_, vr);
            Value k, v;
            if (!read_object(kr, k, depth + 1) || k.type != T::String) return false;
            if (!read_object(vr, v, depth + 1)) return false;
            out.dict.emplace_back(std::move(k.s), std::move(v));
          }
        }
        return true;
      }
      default:
        return false;  // 日付、UID、setはプロトコルで使わない
    }
  }

  const uint8_t* p_;
  size_t n_;
  int off_size_ = 0, ref_size_ = 0;
  uint64_t num_objects_ = 0, table_off_ = 0;
};

}  // namespace

Bytes write_binary(const Value& root) { return Writer().write(root); }

std::optional<Value> parse_binary(const uint8_t* p, size_t n) { return Reader(p, n).parse(); }

}  // namespace iss::plist
