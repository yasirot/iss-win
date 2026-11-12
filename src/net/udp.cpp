#include "net/udp.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>

#include <cstring>
#include <format>
#include <mutex>

#ifndef SIO_UDP_CONNRESET
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
#endif

namespace iss::net {
namespace {

constexpr uintptr_t kInvalid = ~uintptr_t(0);
constexpr size_t kMaxDatagram = 65536;

void ensure_winsock() {
  static std::once_flag once;
  std::call_once(once, [] {
    WSADATA wsa;
    if (int rc = WSAStartup(MAKEWORD(2, 2), &wsa)) throw NetError(std::format("WSAStartup failed ({})", rc));
  });
}

static_assert(sizeof(sockaddr_in6) <= sizeof(Address::raw));

Address to_address(const sockaddr* sa) {
  Address a;
  char buf[INET6_ADDRSTRLEN] = {};
  if (sa->sa_family == AF_INET6) {
    sockaddr_in6 s6;
    std::memcpy(&s6, sa, sizeof(s6));
    s6.sin6_port = 0;
    inet_ntop(AF_INET6, &s6.sin6_addr, buf, sizeof(buf));
    a.text = s6.sin6_scope_id ? std::format("{}%{}", buf, s6.sin6_scope_id) : std::string(buf);
    a.v6 = true;
    a.len = sizeof(s6);
    std::memcpy(a.raw, &s6, sizeof(s6));
  } else {
    sockaddr_in s4;
    std::memcpy(&s4, sa, sizeof(s4));
    s4.sin_port = 0;
    inet_ntop(AF_INET, &s4.sin_addr, buf, sizeof(buf));
    a.text = buf;
    a.len = sizeof(s4);
    std::memcpy(a.raw, &s4, sizeof(s4));
  }
  return a;
}

}  // namespace

std::optional<Address> parse_address(const std::string& literal) {
  ensure_winsock();
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_flags = AI_NUMERICHOST;
  addrinfo* res = nullptr;
  if (getaddrinfo(literal.c_str(), nullptr, &hints, &res) || !res) {
    if (res) freeaddrinfo(res);
    return std::nullopt;
  }
  const Address a = to_address(res->ai_addr);
  freeaddrinfo(res);
  return a;
}

Address resolve_media_host(const std::string& host, Family family) {
  ensure_winsock();
  addrinfo hints{};
  hints.ai_family = family == Family::V4 ? AF_INET : family == Family::V6 ? AF_INET6 : AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  addrinfo* res = nullptr;
  if (int rc = getaddrinfo(host.c_str(), nullptr, &hints, &res); rc || !res) {
    if (res) freeaddrinfo(res);
    throw NetError(std::format("cannot resolve {}{} (getaddrinfo error {})", host,
                               family == Family::V4   ? " to an IPv4 address"
                               : family == Family::V6 ? " to an IPv6 address"
                                                      : "",
                               rc));
  }
  // 最初のIPv4アドレス。なければ最初の（IPv6の）アドレス。
  const addrinfo* pick = res;
  for (const addrinfo* ai = res; ai; ai = ai->ai_next) {
    if (ai->ai_family == AF_INET) {
      pick = ai;
      break;
    }
  }
  const Address a = to_address(pick->ai_addr);
  freeaddrinfo(res);
  return a;
}

UdpSocket::~UdpSocket() { close(); }

UdpSocket::UdpSocket(UdpSocket&& o) noexcept : sock_(o.sock_.exchange(kInvalid)), v6_(o.v6_) {}

UdpSocket& UdpSocket::operator=(UdpSocket&& o) noexcept {
  if (this != &o) {
    close();
    sock_ = o.sock_.exchange(kInvalid);
    v6_ = o.v6_;
  }
  return *this;
}

UdpSocket UdpSocket::bind(uint16_t port, int rcvbuf_bytes) {
  ensure_winsock();
  SOCKET s = ::socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
  bool v6 = s != INVALID_SOCKET;
  if (v6) {
    const DWORD v6_only = 0;
    if (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<const char*>(&v6_only), sizeof(v6_only))) {
      closesocket(s);
      v6 = false;
    }
  }
  if (!v6) s = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (s == INVALID_SOCKET) throw NetError(std::format("UDP socket: WSA error {}", WSAGetLastError()));
  setsockopt(s, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<const char*>(&rcvbuf_bytes), sizeof(rcvbuf_bytes));
  BOOL report_reset = FALSE;
  DWORD ret = 0;
  WSAIoctl(s, SIO_UDP_CONNRESET, &report_reset, sizeof(report_reset), nullptr, 0, &ret, nullptr, nullptr);
  sockaddr_in6 addr6{};
  addr6.sin6_family = AF_INET6;
  addr6.sin6_addr = in6addr_any;
  addr6.sin6_port = htons(port);
  sockaddr_in addr4{};
  addr4.sin_family = AF_INET;
  addr4.sin_addr.s_addr = htonl(INADDR_ANY);
  addr4.sin_port = htons(port);
  const int rc = v6 ? ::bind(s, reinterpret_cast<sockaddr*>(&addr6), sizeof(addr6))
                    : ::bind(s, reinterpret_cast<sockaddr*>(&addr4), sizeof(addr4));
  if (rc == SOCKET_ERROR) {
    const int err = WSAGetLastError();
    closesocket(s);
    throw NetError(std::format("cannot bind UDP port {} (WSA error {}){}", port, err,
                               err == WSAEADDRINUSE ? " — another program on this PC is using it" : ""));
  }
  return UdpSocket(static_cast<uintptr_t>(s), v6);
}

bool UdpSocket::valid() const { return sock_.load() != kInvalid; }

uint16_t UdpSocket::local_port() const {
  sockaddr_storage addr{};
  int len = sizeof(addr);
  if (getsockname(static_cast<SOCKET>(sock_.load()), reinterpret_cast<sockaddr*>(&addr), &len)) return 0;
  return ntohs(addr.ss_family == AF_INET6 ? reinterpret_cast<sockaddr_in6*>(&addr)->sin6_port
                                          : reinterpret_cast<sockaddr_in*>(&addr)->sin_port);
}

bool UdpSocket::send_to(const Address& to, uint16_t port, const uint8_t* p, size_t n) {
  SOCKET s = static_cast<SOCKET>(sock_.load());
  if (s == INVALID_SOCKET || to.len == 0 || (to.v6 && !v6_)) return false;
  sockaddr_in6 a6{};
  sockaddr_in a4{};
  const sockaddr* sa = nullptr;
  int len = 0;
  if (to.v6) {
    std::memcpy(&a6, to.raw, sizeof(a6));
    a6.sin6_port = htons(port);
    sa = reinterpret_cast<sockaddr*>(&a6);
    len = sizeof(a6);
  } else {
    std::memcpy(&a4, to.raw, sizeof(a4));
    if (v6_) {  // デュアルスタックのソケットから `::ffff:a.b.c.d` として送る
      a6.sin6_family = AF_INET6;
      a6.sin6_port = htons(port);
      a6.sin6_addr.s6_addr[10] = a6.sin6_addr.s6_addr[11] = 0xff;
      std::memcpy(&a6.sin6_addr.s6_addr[12], &a4.sin_addr, 4);
      sa = reinterpret_cast<sockaddr*>(&a6);
      len = sizeof(a6);
    } else {
      a4.sin_port = htons(port);
      sa = reinterpret_cast<sockaddr*>(&a4);
      len = sizeof(a4);
    }
  }
  return ::sendto(s, reinterpret_cast<const char*>(p), static_cast<int>(n), 0, sa, len) != SOCKET_ERROR;
}

bool UdpSocket::send_to(const std::string& literal, uint16_t port, const Bytes& b) {
  const std::optional<Address> to = parse_address(literal);
  return to && send_to(*to, port, b.data(), b.size());
}

std::optional<Bytes> UdpSocket::recv(int timeout_ms) {
  SOCKET s = static_cast<SOCKET>(sock_.load());
  if (s == INVALID_SOCKET) throw NetClosed("recv on closed UDP socket");
  WSAPOLLFD pfd{s, POLLRDNORM, 0};
  const int rc = WSAPoll(&pfd, 1, timeout_ms);
  if (rc == 0) return std::nullopt;
  if (rc == SOCKET_ERROR || (pfd.revents & POLLNVAL)) throw NetClosed("UDP socket closed");
  thread_local Bytes buf(kMaxDatagram);
  const int n = ::recv(s, reinterpret_cast<char*>(buf.data()), static_cast<int>(buf.size()), 0);
  if (n == SOCKET_ERROR) {
    const int err = WSAGetLastError();
    // 紛れ込んだICMPか、大きすぎるデータグラム。捨てて続ける。
    if (err == WSAECONNRESET || err == WSAEMSGSIZE || err == WSAENETRESET) return std::nullopt;
    if (!valid()) throw NetClosed("UDP socket closed");
    throw NetError(std::format("UDP recv: WSA error {}", err));
  }
  return Bytes(buf.begin(), buf.begin() + n);
}

void UdpSocket::close() {
  SOCKET s = static_cast<SOCKET>(sock_.exchange(kInvalid));
  if (s != INVALID_SOCKET) closesocket(s);
}

}  // namespace iss::net
