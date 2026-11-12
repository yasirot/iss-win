// レベル付きの最小限のロガー。メッセージは登録したすべてのsinkに送る。既定の
// sinkはstderr（コンソールにつながっているとき）とOutputDebugStringに書く。
#pragma once

#include <format>
#include <functional>
#include <string>
#include <utility>

namespace iss::log {

enum class Level { Debug, Info, Warn, Error };

const char* level_name(Level lv);

using Sink = std::function<void(Level, const std::string&)>;

// sinkを追加し、そのid（remove_sink用）を返す。スレッドセーフ。
int add_sink(Sink sink);
void remove_sink(int id);
void set_min_level(Level lv);
// すべてのメッセージをファイル（UTF-8）にも追記する。空のパスなら追記しない。
// ファイルを開けない（別のプロセスが書き込んでいる）ときはfalse。
bool set_file(const std::wstring& path);

void write(Level lv, const std::string& msg);

template <class... A>
void debug(std::format_string<A...> f, A&&... a) { write(Level::Debug, std::format(f, std::forward<A>(a)...)); }
template <class... A>
void info(std::format_string<A...> f, A&&... a) { write(Level::Info, std::format(f, std::forward<A>(a)...)); }
template <class... A>
void warn(std::format_string<A...> f, A&&... a) { write(Level::Warn, std::format(f, std::forward<A>(a)...)); }
template <class... A>
void error(std::format_string<A...> f, A&&... a) { write(Level::Error, std::format(f, std::forward<A>(a)...)); }

}  // namespace iss::log
