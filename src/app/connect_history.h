// 接続ダイアログのMac一覧。接続したことのあるMac（新しい順）と、パスワードを
// 保存したMac。Win32を呼ばないので、テストから動かせる。
#pragma once

#include <algorithm>
#include <cwctype>
#include <format>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace iss::app {

// 資格情報マネージャーのターゲット名は、kCredentialPrefix + "user@host:port"。
inline constexpr std::wstring_view kCredentialPrefix = L"iShareScreen/iss-win:";

struct HostEntry {
  std::wstring host;
  int port = 5900;
  std::wstring user;
  // 最後に接続したときのオプション。保存したパスワードでしか知らないエントリではfalse。
  bool has_options = false;
  int mode = 0;
  int codec = 0;
  int resolution = 0;
  bool curtain = true;
  bool two_displays = false;
};

inline bool same_target(const HostEntry& a, const HostEntry& b) {
  auto lower = [](std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(), [](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); });
    return s;
  };
  return a.port == b.port && a.user == b.user && lower(a.host) == lower(b.host);
}

// "user@host"。ポートが5900でなければ":port"を付ける（そのときIPv6のホストは角かっこで囲む）。
inline std::wstring entry_label(const HostEntry& e) {
  if (e.port == 5900) return std::format(L"{}@{}", e.user, e.host);
  const bool v6 = e.host.find(L':') != std::wstring::npos;
  return v6 ? std::format(L"{}@[{}]:{}", e.user, e.host, e.port) : std::format(L"{}@{}:{}", e.user, e.host, e.port);
}

// 保存したパスワードのターゲット名 → そのエントリ（オプションなし）。
inline std::optional<HostEntry> parse_credential_target(std::wstring_view target) {
  if (!target.starts_with(kCredentialPrefix)) return std::nullopt;
  target.remove_prefix(kCredentialPrefix.size());
  const size_t at = target.find(L'@');
  const size_t colon = target.rfind(L':');
  if (at == std::wstring_view::npos || colon == std::wstring_view::npos || colon <= at + 1 || at == 0) {
    return std::nullopt;
  }
  const std::wstring_view port_s = target.substr(colon + 1);
  if (port_s.empty() || port_s.size() > 5 || !std::all_of(port_s.begin(), port_s.end(), std::iswdigit)) {
    return std::nullopt;
  }
  const int port = std::stoi(std::wstring(port_s));
  if (port < 1 || port > 65535) return std::nullopt;
  HostEntry e;
  e.user = target.substr(0, at);
  e.host = target.substr(at + 1, colon - at - 1);
  e.port = port;
  return e;
}

// `e`を先頭に入れ、同じ接続先のものと置き換える。最大`cap`件。
inline void remember_entry(std::vector<HostEntry>& list, const HostEntry& e, size_t cap = 10) {
  std::erase_if(list, [&](const HostEntry& x) { return same_target(x, e); });
  list.insert(list.begin(), e);
  if (list.size() > cap) list.resize(cap);
}

// `list`にまだないエントリを末尾に足す。最大`cap`件まで。
inline void merge_entries(std::vector<HostEntry>& list, const std::vector<HostEntry>& more, size_t cap = 10) {
  for (const HostEntry& e : more) {
    if (list.size() >= cap) break;
    if (std::none_of(list.begin(), list.end(), [&](const HostEntry& x) { return same_target(x, e); })) list.push_back(e);
  }
}

}  // namespace iss::app
