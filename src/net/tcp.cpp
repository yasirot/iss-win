#include "net/tcp.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <chrono>
#include <format>
#include <mutex>

namespace iss::net {
namespace {

void ensure_winsock() {
  static std::once_flag once;
  std::call_once(once, [] {
    WSADATA wsa;
    if (int rc = WSAStartup(MAKEWORD(2, 2), &wsa)) throw NetError(std::format("WSAStartup failed ({})", rc));
  });
}

std::string wsa_message(const char* what, int err) {
  char* text = nullptr;
  FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                 nullptr, static_cast<DWORD>(err), MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT),
                 reinterpret_cast<char*>(&text), 0, nullptr);
  std::string msg = std::format("{}: WSA error {}", what, err);
  if (text) {
    std::string t(text);
    LocalFree(text);
    while (!t.empty() && (t.back() == '\n' || t.back() == '\r' || t.back() == ' ')) t.pop_back();
    msg += " (" + t + ")";
  }
  return msg;
}

[[noreturn]] void throw_wsa(const char* what) { throw NetError(wsa_message(what, WSAGetLastError())); }

constexpr uintptr_t kInvalid = ~uintptr_t(0);

}  // namespace

TcpSocket::~TcpSocket() { close(); }

TcpSocket::TcpSocket(TcpSocket&& o) noexcept
    : sock_(o.sock_.exchange(kInvalid)), timeout_ms_(o.timeout_ms_), peer_(std::move(o.peer_)) {}

TcpSocket& TcpSocket::operator=(TcpSocket&& o) noexcept {
  if (this != &o) {
    close();
    sock_ = o.sock_.exchange(kInvalid);
    timeout_ms_ = o.timeout_ms_;
    peer_ = std::move(o.peer_);
  }
  return *this;
}

bool TcpSocket::valid() const { return sock_.load() != kInvalid; }

TcpSocket TcpSocket::connect(const std::string& host, uint16_t port, int timeout_ms) {
  ensure_winsock();
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  addrinfo* res = nullptr;
  std::string port_s = std::to_string(port);
  if (int rc = getaddrinfo(host.c_str(), port_s.c_str(), &hints, &res)) {
    throw NetError(wsa_message(std::format("resolve {}", host).c_str(), rc));
  }

  std::string last_error = "no addresses";
  bool timed_out = false;
  for (addrinfo* ai = res; ai; ai = ai->ai_next) {
    SOCKET s = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (s == INVALID_SOCKET) { last_error = wsa_message("socket", WSAGetLastError()); continue; }

    u_long nb = 1;
    ioctlsocket(s, FIONBIO, &nb);
    int rc = ::connect(s, ai->ai_addr, static_cast<int>(ai->ai_addrlen));
    if (rc == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) {
      WSAPOLLFD pfd{s, POLLWRNORM, 0};
      rc = WSAPoll(&pfd, 1, timeout_ms);
      if (rc == 0) {
        timed_out = true;
        last_error = std::format("connect to {}:{} timed out", host, port);
        closesocket(s);
        continue;
      }
      int err = 0;
      int len = sizeof(err);
      getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&err), &len);
      if (rc < 0 || err) {
        last_error = wsa_message(std::format("connect to {}:{}", host, port).c_str(), err ? err : WSAGetLastError());
        closesocket(s);
        continue;
      }
    } else if (rc == SOCKET_ERROR) {
      last_error = wsa_message(std::format("connect to {}:{}", host, port).c_str(), WSAGetLastError());
      closesocket(s);
      continue;
    }
    nb = 0;
    ioctlsocket(s, FIONBIO, &nb);

    char addr[INET6_ADDRSTRLEN] = {};
    if (ai->ai_family == AF_INET) {
      inet_ntop(AF_INET, &reinterpret_cast<sockaddr_in*>(ai->ai_addr)->sin_addr, addr, sizeof(addr));
    } else {
      inet_ntop(AF_INET6, &reinterpret_cast<sockaddr_in6*>(ai->ai_addr)->sin6_addr, addr, sizeof(addr));
    }
    freeaddrinfo(res);
    TcpSocket out(static_cast<uintptr_t>(s));
    out.peer_ = std::format("{}:{}", addr, port);
    return out;
  }
  freeaddrinfo(res);
  if (timed_out) throw NetTimeout(last_error);
  throw NetError(last_error);
}

void TcpSocket::set_nodelay(bool on) {
  BOOL v = on ? TRUE : FALSE;
  setsockopt(static_cast<SOCKET>(sock_.load()), IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&v),
             sizeof(v));
}

void TcpSocket::send_all(const uint8_t* p, size_t n) {
  SOCKET s = static_cast<SOCKET>(sock_.load());
  if (s == INVALID_SOCKET) throw NetClosed("send on closed socket");
  while (n) {
    int chunk = static_cast<int>(n > (1u << 30) ? (1u << 30) : n);
    int sent = ::send(s, reinterpret_cast<const char*>(p), chunk, 0);
    if (sent == SOCKET_ERROR) throw_wsa("send");
    p += sent;
    n -= static_cast<size_t>(sent);
  }
}

bool TcpSocket::wait_readable(int timeout_ms) {
  SOCKET s = static_cast<SOCKET>(sock_.load());
  if (s == INVALID_SOCKET) throw NetClosed("recv on closed socket");
  WSAPOLLFD pfd{s, POLLRDNORM, 0};
  int rc = WSAPoll(&pfd, 1, timeout_ms);
  if (rc == SOCKET_ERROR) throw_wsa("poll");
  // POLLHUP / POLLERRも「recvがすぐ戻る」（0かエラー）という意味になる。
  return rc > 0;
}

Bytes TcpSocket::recv_exact(size_t n) {
  Bytes out(n);
  size_t got = 0;
  auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms_);
  while (got < n) {
    auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now());
    if (left.count() <= 0 || !wait_readable(static_cast<int>(left.count()))) {
      throw NetTimeout(std::format("recv_exact({}) timed out after {} bytes", n, got));
    }
    int want = static_cast<int>(n - got > (1u << 30) ? (1u << 30) : n - got);
    int rc = ::recv(static_cast<SOCKET>(sock_.load()), reinterpret_cast<char*>(out.data() + got), want, 0);
    if (rc == 0) throw NetClosed("peer closed during recv_exact");
    if (rc == SOCKET_ERROR) throw_wsa("recv");
    got += static_cast<size_t>(rc);
  }
  return out;
}

std::optional<Bytes> TcpSocket::recv_some(size_t max, int timeout_ms, bool peek) {
  if (!wait_readable(timeout_ms)) return std::nullopt;
  Bytes out(max);
  int rc = ::recv(static_cast<SOCKET>(sock_.load()), reinterpret_cast<char*>(out.data()),
                  static_cast<int>(max), peek ? MSG_PEEK : 0);
  if (rc == SOCKET_ERROR) {
    int err = WSAGetLastError();
    // 相手が閉じたあとのリセットは、呼び出し側には通常の切断と同じに見せる。
    if (err == WSAECONNRESET || err == WSAECONNABORTED) return Bytes{};
    throw NetError(wsa_message("recv", err));
  }
  out.resize(static_cast<size_t>(rc));
  return out;
}

void TcpSocket::shutdown() {
  SOCKET s = static_cast<SOCKET>(sock_.load());
  if (s != INVALID_SOCKET) ::shutdown(s, SD_BOTH);
}

void TcpSocket::close() {
  SOCKET s = static_cast<SOCKET>(sock_.exchange(kInvalid));
  if (s != INVALID_SOCKET) closesocket(s);
}

}  // namespace iss::net
