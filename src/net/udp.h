// メディア経路（RTP / RTCP）用のUDPソケット。受信はpollで待つ。デュアルスタックで、
// 1つのソケットがIPv4もIPv6も受ける。
//
// Appleは自分のポート5900/5901からこちらの同じ番号のポートへ対称に送ってくるので、
// こちらのソケットも同じポート番号でbindする。Windows特有の問題として、ICMPの
// port-unreachable（こちらのファイアウォール穴あけのパケットが、相手が待ち受ける前に
// 届いたとき）を受けると、以後のrecvfromがWSAECONNRESETで失敗する。それを
// 避けるためにSIO_UDP_CONNRESETを切る。
#pragma once

#include <atomic>
#include <cstdint>
#include <optional>
#include <string>

#include "core/bytes.h"
#include "net/tcp.h"

namespace iss::net {

// 数値で表した相手のアドレス。IPv4か、リンクローカルならスコープ付きのIPv6。
struct Address {
  std::string text;    // TCP接続とログ用。例 "fe80::1%21"
  bool v6 = false;
  uint8_t raw[28]{};   // sockaddr_in / sockaddr_in6。ポートは0
  int len = 0;
};

enum class Family { Any, V4, V6 };

// 数値のアドレス文字列 → Address。それ以外はnullopt（名前解決はしない）。
std::optional<Address> parse_address(const std::string& literal);

// メディア経路とTCPの制御接続の両方で使うアドレス。Macは制御接続の接続元へ
// 映像を送るので、2つのアドレスはそろっている必要がある。Anyのときは、その名前に
// IPv4アドレスがあればIPv4を選び（WindowsはIPv6を先に並べがちで、ビューアーは
// これまでずっとIPv4を使ってきた）、なければIPv6を選ぶ。指定したファミリーの
// アドレスがなければNetErrorを投げる。
Address resolve_media_host(const std::string& host, Family family = Family::Any);

class UdpSocket {
 public:
  UdpSocket() = default;
  ~UdpSocket();
  UdpSocket(UdpSocket&& o) noexcept;
  UdpSocket& operator=(UdpSocket&& o) noexcept;
  UdpSocket(const UdpSocket&) = delete;
  UdpSocket& operator=(const UdpSocket&) = delete;

  // ローカルのすべてのアドレス（IPv4とIPv6。WindowsにIPv6がなければIPv4だけ）で
  // ポート（0なら空いている任意のポート）をbindし、受信バッファを大きく取る。
  static UdpSocket bind(uint16_t port, int rcvbuf_bytes = 4 << 20);

  bool valid() const;
  uint16_t local_port() const;
  // できる範囲で送り、失敗しても例外ではなくfalseを返す（フィードバックはもともと欠けうる）。
  bool send_to(const Address& to, uint16_t port, const uint8_t* p, size_t n);
  bool send_to(const Address& to, uint16_t port, const Bytes& b) { return send_to(to, port, b.data(), b.size()); }
  // 数値のアドレス文字列で送る（テスト、ループバック用）。
  bool send_to(const std::string& literal, uint16_t port, const Bytes& b);
  // データグラムを1つ受け取る。タイムアウトならnullopt。close()のあとはNetClosedを投げる。
  std::optional<Bytes> recv(int timeout_ms);
  void close();

 private:
  UdpSocket(uintptr_t s, bool v6) : sock_(s), v6_(v6) {}
  std::atomic<uintptr_t> sock_{~uintptr_t(0)};
  bool v6_ = false;  // デュアルスタックのAF_INET6ソケット
};

}  // namespace iss::net
