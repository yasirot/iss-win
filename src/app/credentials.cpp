#include "app/credentials.h"

#include <windows.h>
#include <wincred.h>

#include <format>

#include "app/connect_history.h"

namespace iss::app {
namespace {

std::wstring target(const std::wstring& host, int port, const std::wstring& user) {
  return std::format(L"{}{}@{}:{}", kCredentialPrefix, user, host, port);
}

}  // namespace

std::optional<std::wstring> load_password(const std::wstring& host, int port, const std::wstring& user) {
  if (host.empty() || user.empty()) return std::nullopt;
  PCREDENTIALW cred = nullptr;
  if (!CredReadW(target(host, port, user).c_str(), CRED_TYPE_GENERIC, 0, &cred)) return std::nullopt;
  std::wstring pw(reinterpret_cast<const wchar_t*>(cred->CredentialBlob), cred->CredentialBlobSize / sizeof(wchar_t));
  SecureZeroMemory(cred->CredentialBlob, cred->CredentialBlobSize);
  CredFree(cred);
  return pw;
}

bool save_password(const std::wstring& host, int port, const std::wstring& user, const std::wstring& password) {
  if (host.empty() || user.empty() || password.empty()) return false;
  const std::wstring t = target(host, port, user);
  CREDENTIALW cred{};
  cred.Type = CRED_TYPE_GENERIC;
  cred.TargetName = const_cast<LPWSTR>(t.c_str());
  cred.CredentialBlobSize = static_cast<DWORD>(password.size() * sizeof(wchar_t));
  cred.CredentialBlob = reinterpret_cast<LPBYTE>(const_cast<wchar_t*>(password.data()));
  cred.Persist = CRED_PERSIST_LOCAL_MACHINE;
  cred.UserName = const_cast<LPWSTR>(user.c_str());
  return CredWriteW(&cred, 0) != FALSE;
}

void forget_password(const std::wstring& host, int port, const std::wstring& user) {
  if (host.empty() || user.empty()) return;
  CredDeleteW(target(host, port, user).c_str(), CRED_TYPE_GENERIC, 0);
}

std::vector<std::wstring> saved_password_targets() {
  std::vector<std::wstring> out;
  DWORD n = 0;
  PCREDENTIALW* creds = nullptr;
  const std::wstring filter = std::wstring(kCredentialPrefix) + L"*";
  if (!CredEnumerateW(filter.c_str(), 0, &n, &creds)) return out;
  for (DWORD i = 0; i < n; ++i) {
    if (creds[i]->Type == CRED_TYPE_GENERIC && creds[i]->TargetName) out.emplace_back(creds[i]->TargetName);
  }
  CredFree(creds);
  return out;
}

}  // namespace iss::app
