#include "proto/check.h"

#include <algorithm>
#include <chrono>
#include <format>
#include <utility>

#include "core/log.h"
#include "proto/auth.h"

namespace iss::proto {
namespace {

// AppleのRFBセキュリティタイプ（iShareScreenのdocs/apple_vnc_rfc.md §4.2.1）。
// どちらの認証経路もタイプ33を通る。
// ほかのタイプはレポートに名前を出すためだけに載せている。
constexpr uint8_t kSecTypeRsa1 = 33;

const char* security_type_name(uint8_t t) {
  switch (t) {
    case 30: return "Diffie-Hellman";
    case 33: return "RSA1/SRP";
    case 35: return "Kerberos";
    case 36: return "Direct SRP";
  }
  return "?";
}

struct StageFailed {
  CheckStage stage;
  std::string message;
};

net::TcpSocket open_and_handshake(const CheckOptions& opt, CheckResult& r) {
  const std::string where = std::format("{}:{}", opt.host, opt.port);
  net::TcpSocket sock;
  try {
    sock = net::TcpSocket::connect(opt.host, opt.port, opt.connect_timeout_ms);
  } catch (const net::NetTimeout&) {
    throw StageFailed{CheckStage::Connect,
                      std::format("{} did not respond within {} s. The Mac may be off, on another network, behind "
                                  "a firewall, or its address may have changed.",
                                  where, opt.connect_timeout_ms / 1000)};
  } catch (const net::NetError& e) {
    throw StageFailed{CheckStage::Connect,
                      std::format("{}. Check the host name and port, and that Screen Sharing is on in System "
                                  "Settings > General > Sharing.",
                                  e.what())};
  }
  sock.set_timeout(opt.io_timeout_ms);
  sock.set_nodelay(true);

  std::string version;
  Bytes types;
  try {
    types = do_protocol_handshake(sock, &version);
  } catch (const HandshakeError& e) {
    throw StageFailed{CheckStage::Handshake, e.what()};
  } catch (const net::NetTimeout&) {
    throw StageFailed{CheckStage::Handshake,
                      std::format("{} accepted the TCP but sent no RFB banner within {} s — is this the Screen "
                                  "Sharing port?",
                                  where, opt.io_timeout_ms / 1000)};
  } catch (const net::NetError& e) {
    throw StageFailed{CheckStage::Handshake, std::format("RFB handshake with {} failed: {}", where, e.what())};
  }

  // 切り替え後の試行もつなぎ直して同じバナーを受け取るので、最初の分だけ記録する。
  if (r.server_version.empty()) {
    r.peer = sock.peer();
    r.server_version = version;
    r.security_types = types;
    log::info("{} ({}): {}, security types {}", where, r.peer, version, describe_security_types(types));
    if (std::find(types.begin(), types.end(), kSecTypeRsa1) == types.end()) {
      // それでも試す。通るかどうかは認証の結果で決まる。ただし、この後で失敗したら
      // 原因はたぶんこれ。
      log::warn("host does not offer security type {} (RSA1), which both auth modes use", kSecTypeRsa1);
    }
  }
  return sock;
}

// 新しいTCPで認証を1回試す。受け付けられればtrue、AuthErrorならfalse（呼び出し側は
// もう一方のモードに移る）。それ以外のエラーでは確認を打ち切る。
bool try_auth(const CheckOptions& opt, AuthMode mode, CheckResult& r) {
  using Outcome = AuthAttempt::Outcome;
  net::TcpSocket sock = open_and_handshake(opt, r);
  try {
    Bytes key = mode == AuthMode::Srp ? do_srp_auth(sock, opt.username, opt.password)
                                      : do_nonsrp_auth(sock, opt.username, opt.password);
    secure_wipe(key);  // 接続確認ではセッション鍵を使わない
  } catch (const AuthError& e) {
    log::warn("{} auth rejected: {}", auth_mode_name(mode), e.what());
    r.attempts.push_back({mode, Outcome::Rejected, e.what()});
    return false;
  } catch (const std::exception& e) {
    r.attempts.push_back({mode, Outcome::Error, e.what()});
    throw StageFailed{CheckStage::Auth, std::format("{} auth did not complete: {}", auth_mode_name(mode), e.what())};
  }
  // ClientInitの前に切る。Mac側ではまだ何も準備されていない。
  sock.shutdown();
  r.attempts.push_back({mode, Outcome::Accepted, {}});
  return true;
}

}  // namespace

std::optional<AuthMode> CheckResult::accepted_mode() const {
  for (const AuthAttempt& a : attempts) {
    if (a.outcome == AuthAttempt::Outcome::Accepted) return a.mode;
  }
  return std::nullopt;
}

bool CheckResult::auth_rejected() const {
  return failed_stage == CheckStage::Auth && !attempts.empty() &&
         std::all_of(attempts.begin(), attempts.end(),
                     [](const AuthAttempt& a) { return a.outcome == AuthAttempt::Outcome::Rejected; });
}

CheckResult check_connection(const CheckOptions& opt) {
  const auto started = std::chrono::steady_clock::now();
  CheckResult r;
  const AuthMode order[2] = {opt.auth_mode, opt.auth_mode == AuthMode::Srp ? AuthMode::NonSrp : AuthMode::Srp};
  try {
    if (!try_auth(opt, order[0], r) && !try_auth(opt, order[1], r)) {
      std::string detail;
      for (const AuthAttempt& a : r.attempts) {
        detail += std::format("{}{}: {}", detail.empty() ? "" : "; ", auth_mode_name(a.mode), a.detail);
      }
      throw StageFailed{CheckStage::Auth,
                        std::format("the Mac rejected the user name / password, or this user is not allowed to "
                                    "use Screen Sharing ({})",
                                    detail)};
    }
  } catch (StageFailed& f) {
    r.failed_stage = f.stage;
    r.error = std::move(f.message);
  }
  r.elapsed_s = std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();
  return r;
}

const char* auth_mode_name(AuthMode m) { return m == AuthMode::Srp ? "SRP" : "non-SRP"; }

const char* check_stage_name(CheckStage s) {
  switch (s) {
    case CheckStage::Connect: return "connect";
    case CheckStage::Handshake: return "handshake";
    case CheckStage::Auth: return "auth";
  }
  return "?";
}

std::string describe_security_types(const Bytes& types) {
  std::string out;
  for (uint8_t t : types) out += std::format("{}{} ({})", out.empty() ? "" : ", ", t, security_type_name(t));
  return out.empty() ? "none" : out;
}

}  // namespace iss::proto
