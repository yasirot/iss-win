// iss-check.exe用の接続確認。TCP → RFBハンドシェイク → 認証まで進め、ClientInitの
// 前に切る。Mac側はセッションを作らないので、コンソールユーザー向けのポップアップも
// 仮想ディスプレイもカーテンも出ない。
//
// 認証の順番はconnect_and_negotiateと同じ。まず優先するモードで試し、AuthErrorなら
// もう一方を試す。どちらも新しいTCPで行う。
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "core/bytes.h"
#include "proto/negotiation.h"

namespace iss::proto {

enum class CheckStage { Connect, Handshake, Auth };

struct AuthAttempt {
  enum class Outcome { Accepted, Rejected, Error };  // RejectedはAuthErrorのとき
  AuthMode mode;
  Outcome outcome;
  std::string detail;
};

struct CheckOptions {
  std::string host;
  uint16_t port = 5900;
  std::string username;
  std::string password;
  AuthMode auth_mode = AuthMode::Srp;  // 失敗したらもう一方のモードを試す
  int connect_timeout_ms = 15000;
  int io_timeout_ms = 15000;
};

struct CheckResult {
  std::string peer;            // TCPでつないだ先のaddress:port
  std::string server_version;  // 例 "RFB 003.889"
  Bytes security_types;
  std::vector<AuthAttempt> attempts;
  std::optional<CheckStage> failed_stage;
  std::string error;
  double elapsed_s = 0;

  bool ok() const { return !failed_stage; }
  std::optional<AuthMode> accepted_mode() const;
  // どのモードもAuthErrorで拒否された。ユーザー名かパスワードの誤り、または
  // Screen Sharingを使えないユーザー（認証の途中でTCPが切れた場合とは区別する）。
  bool auth_rejected() const;
};

// ネットワーク、プロトコル、認証の失敗では例外を投げない。失敗した段階と
// 一緒に結果に入れて返す。
CheckResult check_connection(const CheckOptions& opt);

const char* auth_mode_name(AuthMode m);  // "SRP" / "non-SRP"
const char* check_stage_name(CheckStage s);
// "33 (RSA1/SRP), 36 (Direct SRP)"
std::string describe_security_types(const Bytes& types);

}  // namespace iss::proto
