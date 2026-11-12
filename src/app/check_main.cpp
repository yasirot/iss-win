// iss-check.exe。コンソールで使う接続確認ツール。Macに接続してRFBの
// ハンドシェイクと認証（SRP、だめならnon-SRP）を行い、Macにセッションが
// できる前に切断する（proto/check.hを参照）。
//
//   iss-check.exe --host H --user U [--port P] [--auth srp|nonsrp] [--timeout SECONDS] [-v]
//                 [--negotiate [--alt-session] [--no-curtain]]
//
// --negotiateを付けると、代わりにTCPのハンドシェイクを最後まで行い
// （connect_and_negotiateで0x1cの応答まで）、それから切断する。このときMacには
// 一瞬本物のセッションができる。カーテンがかかり、自分以外のユーザーがコンソールに
// ログインしていれば、そのユーザーに許可のポップアップが出る。
//
// パスワードはコマンドラインからは受け取らない（プロセスの一覧やシェルの履歴に
// 残るため）。コンソールではエコーを切って読み、リダイレクトされていれば
// 標準入力の1行目を読む。
//
// 終了コード: 0 認証成功、1 接続できない / 画面共有のホストではない / 認証が
// 終わらなかった、2 ユーザー名かパスワードが拒否された、3 引数の誤り。
#include <windows.h>

#include <chrono>
#include <cwchar>
#include <format>
#include <iterator>
#include <optional>
#include <string>

#include "core/bytes.h"
#include "core/log.h"
#include "proto/auth.h"
#include "proto/check.h"

namespace {

using namespace iss;

constexpr int kExitOk = 0, kExitFailed = 1, kExitRejected = 2, kExitUsage = 3;

constexpr char kUsage[] =
    "使い方: iss-check.exe --host ホスト --user ユーザー名 [オプション]\n"
    "\n"
    "Mac に接続して認証まで行い、セッションを作る前に切断します。\n"
    "映像は流れず、Mac 側に許可のポップアップや仮想ディスプレイも出ません。\n"
    "\n"
    "  --host H           Mac のホスト名か IP アドレス\n"
    "  -u, --user U       ユーザー名\n"
    "  --port P           TCP ポート (既定 5900)\n"
    "  --auth srp|nonsrp  先に試す認証方式 (既定 srp。拒否されたらもう一方も試す)\n"
    "  --timeout SECONDS  接続と受信のタイムアウト (既定 15)\n"
    "  -v, --verbose      詳しいログを出す\n"
    "\n"
    "  --negotiate        認証のあともハンドシェイクを続け、0x1c の応答 (エンコーダの\n"
    "                     キャンバス) を受けたら切断する。Mac 側には一瞬セッションが\n"
    "                     でき、カーテンがかかる。別のユーザーがログイン中なら Mac に\n"
    "                     許可のポップアップが出る (最大 60 秒待つ)\n"
    "  --alt-session      (--negotiate と併用) 別のユーザーがログイン中でも、ポップアップ\n"
    "                     を出さずに自分のユーザーで別セッションを開く\n"
    "  --no-curtain       (--negotiate と併用) カーテンをかけない\n"
    "\n"
    "パスワードは引数では受け取りません。コンソールから実行すると伏せ字で尋ね、\n"
    "パイプで渡すと標準入力の 1 行目を読みます。\n"
    "\n"
    "終了コード: 0 = 成功, 1 = 接続できない / Screen Sharing ではない / 途中で失敗した,\n"
    "            2 = ユーザー名かパスワードが拒否された, 3 = 引数の誤り\n";

std::string narrow(const wchar_t* p, size_t n) {
  if (!n) return {};
  int len = WideCharToMultiByte(CP_UTF8, 0, p, static_cast<int>(n), nullptr, 0, nullptr, nullptr);
  std::string s(len, '\0');
  WideCharToMultiByte(CP_UTF8, 0, p, static_cast<int>(n), s.data(), len, nullptr, nullptr);
  return s;
}
std::string narrow(const std::wstring& w) { return narrow(w.data(), w.size()); }

std::wstring widen(const std::string& s) {
  if (s.empty()) return {};
  int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
  std::wstring w(n, L'\0');
  MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), w.data(), n);
  return w;
}

// コンソールにはWriteConsoleWで書く（どのコードページでも日本語が化けない）。
// リダイレクトされていればUTF-8のバイト列を書く。
void print(DWORD which, const std::string& utf8) {
  HANDLE h = GetStdHandle(which);
  DWORD mode = 0, written = 0;
  if (GetConsoleMode(h, &mode)) {
    const std::wstring w = widen(utf8);
    WriteConsoleW(h, w.data(), static_cast<DWORD>(w.size()), &written, nullptr);
  } else {
    WriteFile(h, utf8.data(), static_cast<DWORD>(utf8.size()), &written, nullptr);
  }
}
void out(const std::string& s) { print(STD_OUTPUT_HANDLE, s); }
void err(const std::string& s) { print(STD_ERROR_HANDLE, s); }

// パスワード入力中にCtrl+Cを押されても、コンソールのエコーを切ったままにしない。
DWORD g_saved_input_mode = 0;
volatile bool g_input_mode_changed = false;
BOOL WINAPI restore_echo_on_ctrl(DWORD) {
  if (g_input_mode_changed) SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), g_saved_input_mode);
  return FALSE;  // そのまま既定のハンドラーに任せる（終了する）
}

std::string read_password() {
  HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
  if (GetConsoleMode(in, &g_saved_input_mode)) {
    err("password: ");
    SetConsoleCtrlHandler(restore_echo_on_ctrl, TRUE);
    SetConsoleMode(in, (g_saved_input_mode & ~ENABLE_ECHO_INPUT) | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT);
    g_input_mode_changed = true;
    std::wstring line;
    wchar_t buf[128];
    DWORD n = 0;
    while (ReadConsoleW(in, buf, static_cast<DWORD>(std::size(buf)), &n, nullptr) && n > 0) {
      line.append(buf, n);
      if (line.back() == L'\n') break;
    }
    SetConsoleMode(in, g_saved_input_mode);
    g_input_mode_changed = false;
    err("\n");
    while (!line.empty() && (line.back() == L'\n' || line.back() == L'\r')) line.pop_back();
    std::string pw = narrow(line);
    secure_wipe(line.data(), line.size() * sizeof(wchar_t));
    secure_wipe(buf, sizeof(buf));
    return pw;
  }
  std::string line;
  char c = 0;
  DWORD n = 0;
  while (ReadFile(in, &c, 1, &n, nullptr) && n == 1 && c != '\n') line.push_back(c);
  if (!line.empty() && line.back() == '\r') line.pop_back();
  if (line.starts_with("\xEF\xBB\xBF")) line.erase(0, 3);  // シェルによっては付くUTF-8のBOM
  return line;
}

struct Args {
  proto::CheckOptions opt;
  bool negotiate = false;
  bool alt_session = false;
  bool curtain = true;
  bool verbose = false;
  bool help = false;
};

// 解析した引数を返す。誤りがあればエラーメッセージを返す。
std::optional<Args> parse_args(int argc, wchar_t** argv, std::string& error) {
  Args a;
  for (int i = 1; i < argc; ++i) {
    const std::wstring k = argv[i];
    auto value = [&]() -> std::optional<std::wstring> {
      if (i + 1 < argc) return argv[++i];
      error = std::format("{} には値が必要です", narrow(k));
      return std::nullopt;
    };
    auto number = [&](int lo, int hi) -> std::optional<int> {
      auto v = value();
      if (!v) return std::nullopt;
      wchar_t* end = nullptr;
      const long n = std::wcstol(v->c_str(), &end, 10);
      if (v->empty() || *end || n < lo || n > hi) {
        error = std::format("{} は {}〜{} の整数で指定してください (指定値: {})", narrow(k), lo, hi, narrow(*v));
        return std::nullopt;
      }
      return static_cast<int>(n);
    };
    if (k == L"-h" || k == L"--help") {
      a.help = true;
    } else if (k == L"-v" || k == L"--verbose") {
      a.verbose = true;
    } else if (k == L"--negotiate") {
      a.negotiate = true;
    } else if (k == L"--alt-session") {
      a.alt_session = true;
    } else if (k == L"--no-curtain") {
      a.curtain = false;
    } else if (k == L"--host") {
      auto v = value();
      if (!v) return std::nullopt;
      a.opt.host = narrow(*v);
    } else if (k == L"-u" || k == L"--user") {
      auto v = value();
      if (!v) return std::nullopt;
      a.opt.username = narrow(*v);
    } else if (k == L"--port") {
      auto v = number(1, 65535);
      if (!v) return std::nullopt;
      a.opt.port = static_cast<uint16_t>(*v);
    } else if (k == L"--timeout") {
      auto v = number(1, 600);
      if (!v) return std::nullopt;
      a.opt.connect_timeout_ms = a.opt.io_timeout_ms = *v * 1000;
    } else if (k == L"--auth") {
      auto v = value();
      if (!v) return std::nullopt;
      if (*v == L"srp") {
        a.opt.auth_mode = proto::AuthMode::Srp;
      } else if (*v == L"nonsrp") {
        a.opt.auth_mode = proto::AuthMode::NonSrp;
      } else {
        error = std::format("--auth は srp か nonsrp です (指定値: {})", narrow(*v));
        return std::nullopt;
      }
    } else if (k == L"--password" || k == L"-p") {
      error = "パスワードは引数では受け取りません (コンソールで入力するか、標準入力に渡してください)";
      return std::nullopt;
    } else {
      error = std::format("不明な引数: {}", narrow(k));
      return std::nullopt;
    }
  }
  if (a.help) return a;
  if (a.opt.host.empty() || a.opt.username.empty()) {
    error = "--host と --user は必須です";
    return std::nullopt;
  }
  if (!a.negotiate && (a.alt_session || !a.curtain)) {
    error = "--alt-session と --no-curtain は --negotiate と一緒に指定してください";
    return std::nullopt;
  }
  return a;
}

const char* outcome_text(proto::AuthAttempt::Outcome o) {
  switch (o) {
    case proto::AuthAttempt::Outcome::Accepted: return "成功";
    case proto::AuthAttempt::Outcome::Rejected: return "拒否";
    case proto::AuthAttempt::Outcome::Error: return "中断";
  }
  return "?";
}

const char* stage_text(proto::CheckStage s) {
  switch (s) {
    case proto::CheckStage::Connect: return "TCP 接続";
    case proto::CheckStage::Handshake: return "RFB ハンドシェイク";
    case proto::CheckStage::Auth: return "認証";
  }
  return "?";
}

void print_report(const proto::CheckOptions& opt, const proto::CheckResult& r) {
  std::string s = std::format("接続確認: {}:{}  ユーザー {}\n", opt.host, opt.port, opt.username);
  if (!r.peer.empty()) s += std::format("  接続先        {}\n", r.peer);
  if (!r.server_version.empty()) {
    s += std::format("  サーバ        {}\n", r.server_version);
    s += std::format("  セキュリティ  {}\n", proto::describe_security_types(r.security_types));
  }
  for (const proto::AuthAttempt& a : r.attempts) {
    s += std::format("  {:<12}  {}{}{}\n", proto::auth_mode_name(a.mode), outcome_text(a.outcome),
                     a.detail.empty() ? "" : ": ", a.detail);
  }
  if (r.ok()) {
    s += std::format("結果: OK — {} 認証が通りました ({:.1f} 秒)\n", proto::auth_mode_name(*r.accepted_mode()),
                     r.elapsed_s);
  } else {
    s += std::format("結果: NG — {}で失敗しました ({:.1f} 秒)\n  {}\n", stage_text(*r.failed_stage), r.elapsed_s,
                     r.error);
  }
  out(s);
}

// --negotiate。connect_and_negotiateで0x1cの応答まで進め、それから切断する。
// UDPのソケットはbindしないので、Macが送り始めるメディアは捨てられる。
// 確かめるのはTCPの側だけだ。
int run_negotiate(const Args& a) {
  const proto::CheckOptions& c = a.opt;
  proto::ConnectOptions opt;
  opt.host = c.host;
  opt.port = c.port;
  opt.username = c.username;
  opt.password = c.password;
  opt.auth_mode = c.auth_mode;
  opt.curtain = a.curtain;
  opt.alt_session = a.alt_session;
  opt.timing.connect_timeout_ms = c.connect_timeout_ms;
  opt.timing.io_timeout_ms = c.io_timeout_ms;
  std::string console_user;
  opt.on_session_choice = [&, ack_s = opt.timing.ss_ack_ms / 1000](const std::string& user) {
    console_user = user;
    err(std::format("Mac には別のユーザー ({}) がログインしています。Mac 側の許可ポップアップで"
                    "「許可」を押してください (最大 {} 秒待ちます)\n",
                    user, ack_s));
    return proto::SessionChoice::ShareConsole;
  };

  err("注意: Mac 側に実際のセッションを作ります。0x1c の応答を受けたら切断します。\n");
  std::string s = std::format("ネゴシエーション確認: {}:{}  ユーザー {}\n", c.host, c.port, c.username);
  const auto started = std::chrono::steady_clock::now();
  auto elapsed = [&] { return std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count(); };
  auto fail = [&](const char* where, const char* what) {
    s += std::format("結果: NG — {}で失敗しました ({:.1f} 秒)\n  {}\n", where, elapsed(), what);
  };
  int code = kExitFailed;
  try {
    proto::NegotiationResult r = proto::connect_and_negotiate(opt);
    r.sock.shutdown();
    r.sock.close();
    secure_wipe(r.ecb_key);
    s += std::format("  ServerInit    {}x{}\n", r.server_width, r.server_height);
    s += std::format("  セッション    {}\n", r.alt_session            ? "別セッション (cmd=2)"
                                           : !console_user.empty() ? "コンソールと共有 (cmd=0)"
                                                                   : "SessionSelect なし");
    if (r.canvas.valid()) {
      s += std::format("  キャンバス    {}x{}, {} タイル{}\n", r.canvas.width, r.canvas.height, r.canvas.tiles,
                       r.canvas.ltrp ? std::format(", LTRP {}", *r.canvas.ltrp ? "on" : "off") : "");
      s += std::format("  先行受信      {} 件 (カーソルなど、応答と一緒に届いたメッセージ)\n", r.leftover_msgs.size());
      s += std::format("結果: OK — 0x1c の応答まで通りました ({:.1f} 秒)\n", elapsed());
      code = kExitOk;
    } else {
      fail("0x1c の応答", "エンコーダのキャンバスが返ってきませんでした (再問い合わせも上限まで失敗)");
    }
  } catch (const proto::AuthError& e) {
    fail("認証", e.what());
    code = kExitRejected;
  } catch (const proto::HandshakeError& e) {
    fail("ハンドシェイク", e.what());
  } catch (const net::NetTimeout& e) {
    fail("通信 (タイムアウト)", e.what());
  } catch (const net::NetError& e) {
    fail("通信", e.what());
  } catch (const std::exception& e) {
    fail("ネゴシエーション", e.what());
  }
  secure_wipe(opt.password);
  out(s);
  return code;
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
  std::string error;
  std::optional<Args> args = parse_args(argc, argv, error);
  if (!args) {
    err(std::format("iss-check: {}\n\n{}", error, kUsage));
    return kExitUsage;
  }
  if (args->help) {
    out(kUsage);
    return kExitOk;
  }
  // --negotiateではハンドシェイクの進み具合を出す。Mac側でクリックされるまで
  // 1分ほど待つことがあるため。
  log::set_min_level(args->verbose ? log::Level::Debug : args->negotiate ? log::Level::Info : log::Level::Warn);

  proto::CheckOptions& opt = args->opt;
  opt.password = read_password();
  if (opt.password.empty()) {
    err("iss-check: パスワードが空です\n");
    return kExitUsage;
  }
  if (args->negotiate) {
    const int code = run_negotiate(*args);
    secure_wipe(opt.password);
    return code;
  }
  const proto::CheckResult r = proto::check_connection(opt);
  secure_wipe(opt.password);

  print_report(opt, r);
  if (r.ok()) return kExitOk;
  return r.auth_rejected() ? kExitRejected : kExitFailed;
}
