// SRTP / SRTCP、RTCPの組み立て、H.264 SPSのDPB書き換え、UDPソケット。
// test_main.cppがsession_tests.incの後に読み込む（TEST / CHECK / H() /
// HEXLISTが使える）。
#include <winsock2.h>

#include "media/nalu.h"
#include "net/udp.h"
#include "proto/rtcp.h"
#include "proto/srtp.h"

namespace {

// ── SRTP / SRTCP ─────────────────────────────────────────────────────────

TEST(srtp_kdf_matches_python) {
  const Bytes blob = H(kSrtpBlob);
  const Bytes key(blob.begin(), blob.begin() + 32), salt(blob.begin() + 32, blob.end());
  CHECK_HEX(proto::srtp_kdf(key, salt, 0, 32), kSrtpKdfRtpCipher);
  CHECK_HEX(proto::srtp_kdf(key, salt, 5, 14), kSrtpKdfRtcpSalt);
}

TEST(srtp_encrypt_matches_python) {
  const auto plain = HEXLIST(kSrtpPlain);
  const auto want = HEXLIST(kSrtpFresh);
  proto::SrtpEncryptor enc(H(kSrtpBlob), 0x5EED1234);
  for (size_t i = 0; i < plain.size(); ++i) CHECK_HEX(enc.encrypt(plain[i], 101, i == 1), to_hex(want[i]));
}

TEST(srtp_decrypt_follows_roc_wrap) {
  const auto plain = HEXLIST(kSrtpPlain);
  const auto pkts = HEXLIST(kSrtpWrap);
  proto::SrtpDecryptor dec(H(kSrtpBlob));
  const uint16_t seqs[] = {0xFFFE, 0xFFFF, 0, 1};
  for (size_t i = 0; i < pkts.size(); ++i) {
    const auto p = dec.decrypt(pkts[i]);
    CHECK(p.has_value());
    if (!p) continue;
    CHECK(p->payload == plain[i]);
    CHECK(p->seq == seqs[i] && p->ssrc == 0x5EED1234 && p->pt == 96 && p->marker == (i == 1));
  }
  CHECK(dec.counts().at(0x5EED1234) == pkts.size());
}

TEST(srtp_decrypt_header_extension) {
  proto::SrtpDecryptor dec(H(kSrtpBlob));
  const auto p = dec.decrypt(H(kSrtpExtPacket));
  CHECK(p.has_value());
  if (!p) return;
  CHECK(p->header_len == static_cast<size_t>(kSrtpExtHeaderLen));
  CHECK_HEX(p->payload, kSrtpExtPayload);
  CHECK(p->marker && p->pt == 96 && p->seq == 0x1234 && p->ts == 0x01020304 && p->ssrc == 0x0A0B0C0D);
}

TEST(srtp_rejects_tampering) {
  proto::SrtpDecryptor dec(H(kSrtpBlob));
  Bytes pkt = HEXLIST(kSrtpWrap)[1];
  pkt[40] ^= 1;
  CHECK(!dec.decrypt(pkt));
  CHECK(!dec.decrypt(Bytes(21, 0x80)));  // ヘッダ + タグより短い
  CHECK(dec.counts().empty());
}

TEST(srtcp_matches_python) {
  const auto plain = HEXLIST(kSrtcpPlain);
  const auto pkts = HEXLIST(kSrtcpPackets);
  proto::SrtcpEncryptor enc(H(kSrtpBlob));
  proto::SrtcpDecryptor dec(H(kSrtpBlob));
  for (size_t i = 0; i < plain.size(); ++i) {
    CHECK_HEX(enc.protect(plain[i]), to_hex(pkts[i]));
    const auto back = dec.unprotect(pkts[i].data(), pkts[i].size());
    CHECK(back && *back == plain[i]);
  }
  Bytes bad = pkts[1];
  bad[9] ^= 0x40;
  CHECK(!dec.unprotect(bad.data(), bad.size()));
}

// ── RTCP ─────────────────────────────────────────────────────────────────

TEST(rtcp_builders_match_python) {
  namespace rtcp = proto::rtcp;
  CHECK_HEX(rtcp::build_fir(0xA1A2A3A4, 0xB1B2B3B4, 0xFF), kRtcpFir);
  CHECK_HEX(rtcp::build_fir_legacy(0xB1B2B3B4), kRtcpFirLegacy);
  CHECK_HEX(rtcp::build_pli(0xA1A2A3A4, 0xB1B2B3B4), kRtcpPli);
  CHECK_HEX(rtcp::build_nack(0xA1A2A3A4, 0xB1B2B3B4, {100, 101, 116, 117, 140, 65535, 0, 3, 101}), kRtcpNack);
  CHECK(rtcp::build_nack(1, 2, {}).empty());
  CHECK_HEX(rtcp::build_app_ltrp(0xA1A2A3A4, 0x12345), kRtcpLtrp);
  CHECK_HEX(rtcp::build_rr(0xA1A2A3A4, {{.ssrc = 0xB1, .roc = 3, .max_seq = 0xFFFE}, {.ssrc = 0xB2, .roc = 0x10001, .max_seq = 7}}),
            kRtcpRr);
  CHECK_HEX(rtcp::build_rr(0xA1A2A3A4), kRtcpRrEmpty);
  CHECK(rtcp::compound_with_rr(7, H("aabb")) == ByteWriter().bytes(rtcp::build_rr(7)).bytes(H("aabb")).take());
}

TEST(rtcp_sender_report) {
  const auto sr = proto::rtcp::parse_sr_arrivals(H(kRtcpSrCompound));
  CHECK(sr.size() == 1);
  if (!sr.empty()) CHECK(sr[0].ssrc == static_cast<uint32_t>(kRtcpSrSsrc) && sr[0].ntp_mid32 == static_cast<uint32_t>(kRtcpSrMid32));

  const Bytes mine = proto::rtcp::build_empty_sr(0x01020304, 1700000000.5);
  CHECK(mine.size() == 28 && mine[1] == 200 && rd_be32(&mine[4]) == 0x01020304);
  CHECK(rd_be32(&mine[8]) == static_cast<uint32_t>(1700000000ull + 2208988800ull));
  CHECK(rd_be32(&mine[12]) == 0x80000000u);
  CHECK(rd_be32(&mine[16]) == static_cast<uint32_t>(1700000000ull * 90000ull + 45000ull));
}

// ── H.264 SPSのDPB書き換え ──────────────────────────────────────────────────

TEST(sps_dpb_patch_matches_python) {
  const auto in = HEXLIST(kSpsIn);
  const auto want = HEXLIST(kSpsPatched);
  CHECK(in.size() == want.size());
  for (size_t i = 0; i < in.size() && i < want.size(); ++i) CHECK_HEX(media::patch_avc_sps_dpb(in[i]), to_hex(want[i]));
  CHECK(media::patch_avc_sps_dpb(H("68ce3c80")) == H("68ce3c80"));  // PPSはそのまま通す
}

// ── UDP ──────────────────────────────────────────────────────────────────

TEST(udp_loopback_roundtrip) {
  net::UdpSocket a = net::UdpSocket::bind(0), b = net::UdpSocket::bind(0);
  CHECK(a.local_port() && b.local_port() && a.local_port() != b.local_port());
  CHECK(!b.recv(50).has_value());  // タイムアウト
  CHECK(a.send_to("127.0.0.1", b.local_port(), H("01020304")));
  const auto got = b.recv(2000);
  CHECK(got && *got == H("01020304"));

  // ICMPのport unreachableを受けても、後の受信を失敗させない（SIO_UDP_CONNRESET）。
  uint16_t dead = 0;
  {
    net::UdpSocket tmp = net::UdpSocket::bind(0);
    dead = tmp.local_port();
  }
  a.send_to("127.0.0.1", dead, H("00"));
  Sleep(50);
  bool threw = false;
  try {
    a.recv(50);
  } catch (const net::NetError&) {
    threw = true;
  }
  CHECK(!threw);
  CHECK(b.send_to("127.0.0.1", a.local_port(), H("ff")));
  const auto back = a.recv(2000);
  CHECK(back && *back == H("ff"));

  a.close();
  threw = false;
  try {
    a.recv(10);
  } catch (const net::NetClosed&) {
    threw = true;
  }
  CHECK(threw);
}

TEST(udp_dual_stack_takes_ipv6_and_ipv4) {
  net::UdpSocket a = net::UdpSocket::bind(0), b = net::UdpSocket::bind(0);
  CHECK(a.send_to("::1", b.local_port(), H("0606")));
  const auto v6 = b.recv(2000);
  CHECK(v6 && *v6 == H("0606"));
  CHECK(a.send_to("127.0.0.1", b.local_port(), H("0404")));  // 同じソケットで、IPv4は::ffff:127.0.0.1として受ける
  const auto v4 = b.recv(2000);
  CHECK(v4 && *v4 == H("0404"));
  CHECK(!a.send_to("not-an-address", b.local_port(), H("00")));
}

TEST(parse_address_keeps_family_and_scope) {
  const auto v4 = net::parse_address("192.0.2.98");
  CHECK(v4 && !v4->v6 && v4->text == "192.0.2.98");
  const auto v6 = net::parse_address("2001:db8:10:7001::f754");
  CHECK(v6 && v6->v6 && v6->text == "2001:db8:10:7001::f754");
  const auto link = net::parse_address("fe80::1234:5678:9abc:def0%21");
  CHECK(link && link->v6 && link->text == "fe80::1234:5678:9abc:def0%21");
  CHECK(!net::parse_address("macBox"));  // 名前にはresolve_media_hostが要る
}

TEST(resolve_media_host_prefers_ipv4_unless_asked) {
  CHECK(net::resolve_media_host("127.0.0.1").text == "127.0.0.1");
  CHECK(net::resolve_media_host("::1").text == "::1");
  // localhostは両方を持つ。既定ではIPv4、指定すればIPv6かIPv4だけ。
  CHECK(net::resolve_media_host("localhost").text == "127.0.0.1");
  CHECK(net::resolve_media_host("localhost", net::Family::V6).text == "::1");
  CHECK(net::resolve_media_host("localhost", net::Family::V4).text == "127.0.0.1");
  bool threw = false;
  try {
    net::resolve_media_host("127.0.0.1", net::Family::V6);
  } catch (const net::NetError&) {
    threw = true;
  }
  CHECK(threw);
}

}  // namespace
