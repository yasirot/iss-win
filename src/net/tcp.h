// pollでタイムアウトを取る、ブロッキングのTCPソケット（SO_RCVTIMEOはタイムアウト
// のあとWinsockのソケットを不定な状態にするので使わない）。
#pragma once

#include <atomic>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>

#include "core/bytes.h"

namespace iss::net {

class NetError : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

// recv_exact / connectが時間切れになった。
class NetTimeout : public NetError {
 public:
  using NetError::NetError;
};

// 相手が接続を閉じた。
class NetClosed : public NetError {
 public:
  using NetError::NetError;
};

class TcpSocket {
 public:
  static constexpr int kDefaultTimeoutMs = 15000;

  TcpSocket() = default;
  ~TcpSocket();
  TcpSocket(TcpSocket&& o) noexcept;
  TcpSocket& operator=(TcpSocket&& o) noexcept;
  TcpSocket(const TcpSocket&) = delete;
  TcpSocket& operator=(const TcpSocket&) = delete;

  // `host`（IPv4/IPv6/名前）を名前解決し、得たアドレスを順に試して接続する。
  static TcpSocket connect(const std::string& host, uint16_t port, int timeout_ms);

  bool valid() const;
  void set_nodelay(bool on);
  // recv_exactが使う既定のタイムアウト。
  void set_timeout(int ms) { timeout_ms_ = ms; }
  int timeout() const { return timeout_ms_; }

  void send_all(const uint8_t* p, size_t n);
  void send_all(const Bytes& b) { send_all(b.data(), b.size()); }

  // ちょうどnバイト受け取る。受け取れなければ例外（NetTimeout / NetClosed / NetError）。
  Bytes recv_exact(size_t n);
  // 最大 `max` バイト受け取る。タイムアウトならnullopt、相手が閉じたら空のvector。
  std::optional<Bytes> recv_some(size_t max, int timeout_ms, bool peek = false);

  // 送受信の両方向をshutdownする。待ち中のrecvを抜けさせるために、別のスレッド
  // から呼んでも安全。
  void shutdown();
  void close();

  std::string peer() const { return peer_; }

 private:
  explicit TcpSocket(uintptr_t s) : sock_(s) {}
  bool wait_readable(int timeout_ms);

  std::atomic<uintptr_t> sock_{~uintptr_t(0)};  // INVALID_SOCKET
  int timeout_ms_ = kDefaultTimeoutMs;
  std::string peer_;
};

}  // namespace iss::net
