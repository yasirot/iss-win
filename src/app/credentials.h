// Macのパスワードを、Windowsの資格情報マネージャーに保存する。ホスト、ポート、
// ユーザーごとに汎用資格情報を1つ作り（"iShareScreen/iss-win:user@host:port"）、
// 今のWindowsユーザーだけが読める。コントロールパネル > 資格情報マネージャー >
// Windows資格情報で確認・削除できる。
#pragma once

#include <optional>
#include <string>
#include <vector>

namespace iss::app {

std::optional<std::wstring> load_password(const std::wstring& host, int port, const std::wstring& user);
bool save_password(const std::wstring& host, int port, const std::wstring& user, const std::wstring& password);
void forget_password(const std::wstring& host, int port, const std::wstring& user);
// 保存したパスワードすべてのターゲット名（parse_credential_targetで解析する）。
std::vector<std::wstring> saved_password_targets();

}  // namespace iss::app
