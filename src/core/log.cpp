#include "core/log.h"

#include <windows.h>

#include <share.h>

#include <chrono>
#include <cstdio>
#include <map>
#include <mutex>

namespace iss::log {
namespace {

struct State {
  std::mutex mu;
  std::map<int, Sink> sinks;
  int next_id = 1;
  Level min_level = Level::Info;
  FILE* file = nullptr;
};

State& state() {
  static State s;
  return s;
}

std::string timestamp() {
  SYSTEMTIME t;
  GetLocalTime(&t);
  return std::format("{:02}:{:02}:{:02}.{:03}", t.wHour, t.wMinute, t.wSecond, t.wMilliseconds);
}

}  // namespace

const char* level_name(Level lv) {
  switch (lv) {
    case Level::Debug: return "DEBUG";
    case Level::Info: return "INFO";
    case Level::Warn: return "WARNING";
    case Level::Error: return "ERROR";
  }
  return "?";
}

int add_sink(Sink sink) {
  auto& s = state();
  std::lock_guard lk(s.mu);
  int id = s.next_id++;
  s.sinks.emplace(id, std::move(sink));
  return id;
}

void remove_sink(int id) {
  auto& s = state();
  std::lock_guard lk(s.mu);
  s.sinks.erase(id);
}

void set_min_level(Level lv) {
  auto& s = state();
  std::lock_guard lk(s.mu);
  s.min_level = lv;
}

bool set_file(const std::wstring& path) {
  auto& s = state();
  std::lock_guard lk(s.mu);
  if (s.file) { fclose(s.file); s.file = nullptr; }
  // アプリの実行中にもログを見られるよう、読み取りは共有にする。
  if (!path.empty()) s.file = _wfsopen(path.c_str(), L"ab", _SH_DENYWR);
  return s.file != nullptr;
}

void write(Level lv, const std::string& msg) {
  auto& s = state();
  std::lock_guard lk(s.mu);
  if (lv < s.min_level) return;
  std::string line = std::format("{} {} {}\n", timestamp(), level_name(lv), msg);
  OutputDebugStringA(line.c_str());
  if (GetConsoleWindow()) {
    fputs(line.c_str(), stderr);
    fflush(stderr);
  }
  if (s.file) {
    fputs(line.c_str(), s.file);
    fflush(s.file);
  }
  for (auto& [id, sink] : s.sinks) sink(lv, msg);
}

}  // namespace iss::log
