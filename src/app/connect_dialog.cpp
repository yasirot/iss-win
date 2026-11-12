#include "app/connect_dialog.h"

#include <windowsx.h>

#include <format>
#include <memory>

#include "app/connect_history.h"
#include "app/credentials.h"
#include "app/resource.h"
#include "core/bytes.h"

namespace iss::app {
namespace {

constexpr wchar_t kRegKey[] = L"Software\\iShareScreen\\iss-win";
constexpr wchar_t kHostsKey[] = L"Software\\iShareScreen\\iss-win\\Hosts";  // サブキー0, 1, …。新しい順
constexpr size_t kMaxHosts = 10;

struct DialogState {
  const std::vector<GpuInfo>* gpus;
  ConnectSettings* settings;
  const ConnectFn* connect;
  std::vector<HostEntry> entries;  // 接続先の一覧の項目i + 1（項目0は新しい接続先）
  bool filling = false;            // 一覧の項目から入力欄を埋めている最中。一覧との照合はしない
  bool connecting = false;
  ConnectSettings pending;         // 接続に使っている設定。パスワードは保存のためだけに持つ
  bool remember = false;
};

std::wstring reg_get_string(HKEY key, const wchar_t* name) {
  wchar_t buf[512];
  DWORD size = sizeof(buf);
  DWORD type = 0;
  if (RegQueryValueExW(key, name, nullptr, &type, reinterpret_cast<BYTE*>(buf), &size) != ERROR_SUCCESS ||
      type != REG_SZ) {
    return {};
  }
  buf[std::min<size_t>(size / sizeof(wchar_t), std::size(buf) - 1)] = 0;
  return buf;
}

bool reg_get_dword(HKEY key, const wchar_t* name, DWORD& out) {
  DWORD size = sizeof(out);
  DWORD type = 0;
  return RegQueryValueExW(key, name, nullptr, &type, reinterpret_cast<BYTE*>(&out), &size) == ERROR_SUCCESS &&
         type == REG_DWORD;
}

void load_saved_impl(ConnectSettings& s, const std::vector<GpuInfo>& gpus) {
  HKEY key;
  if (RegOpenKeyExW(HKEY_CURRENT_USER, kRegKey, 0, KEY_READ, &key) != ERROR_SUCCESS) return;
  if (s.host.empty()) s.host = reg_get_string(key, L"Host");
  if (s.user.empty()) s.user = reg_get_string(key, L"User");
  DWORD v;
  // コマンドラインでポートを指定していれば（既定値以外なら）そちらを優先する。
  if (s.port == 5900 && reg_get_dword(key, L"Port", v) && v > 0 && v < 65536) s.port = static_cast<int>(v);
  if (reg_get_dword(key, L"ResolutionMode", v) && v < resolution_choices().size()) s.resolution = static_cast<int>(v);
  if (reg_get_dword(key, L"Mode", v) && v < mode_choices().size()) s.mode = static_cast<int>(v);
  if (reg_get_dword(key, L"Codec", v) && v < codec_choices().size()) s.codec = static_cast<int>(v);
  if (reg_get_dword(key, L"Curtain", v)) s.curtain = v != 0;
  if (reg_get_dword(key, L"TwoDisplays", v)) s.two_displays = v != 0;
  // GPUは名前で保存する。DXGIのインデックスはアダプタが増えたり減ったりするとずれる。
  if (s.gpu < 0) {
    std::wstring name = reg_get_string(key, L"Gpu");
    for (const auto& g : gpus) {
      if (!name.empty() && g.name == name) s.gpu = static_cast<int>(g.index);
    }
  }
  RegCloseKey(key);
}

void save(const ConnectSettings& s, const std::vector<GpuInfo>& gpus) {
  HKEY key;
  if (RegCreateKeyExW(HKEY_CURRENT_USER, kRegKey, 0, nullptr, 0, KEY_WRITE, nullptr, &key, nullptr) != ERROR_SUCCESS) {
    return;
  }
  auto put_str = [&](const wchar_t* name, const std::wstring& v) {
    RegSetValueExW(key, name, 0, REG_SZ, reinterpret_cast<const BYTE*>(v.c_str()),
                   static_cast<DWORD>((v.size() + 1) * sizeof(wchar_t)));
  };
  auto put_dword = [&](const wchar_t* name, DWORD v) {
    RegSetValueExW(key, name, 0, REG_DWORD, reinterpret_cast<const BYTE*>(&v), sizeof(v));
  };
  put_str(L"Host", s.host);
  put_str(L"User", s.user);
  put_dword(L"Port", static_cast<DWORD>(s.port));
  put_dword(L"ResolutionMode", static_cast<DWORD>(s.resolution));
  put_dword(L"Mode", static_cast<DWORD>(s.mode));
  put_dword(L"Codec", static_cast<DWORD>(s.codec));
  put_dword(L"Curtain", s.curtain ? 1 : 0);
  put_dword(L"TwoDisplays", s.two_displays ? 1 : 0);
  put_str(L"Gpu", s.gpu >= 0 && static_cast<size_t>(s.gpu) < gpus.size() ? gpus[s.gpu].name : L"");
  RegCloseKey(key);
}

std::vector<HostEntry> load_history() {
  std::vector<HostEntry> out;
  for (size_t i = 0; i < kMaxHosts; ++i) {
    HKEY key;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, std::format(L"{}\\{}", kHostsKey, i).c_str(), 0, KEY_READ, &key) !=
        ERROR_SUCCESS) {
      break;
    }
    HostEntry e;
    e.host = reg_get_string(key, L"Host");
    e.user = reg_get_string(key, L"User");
    e.has_options = true;
    DWORD v;
    if (reg_get_dword(key, L"Port", v) && v > 0 && v < 65536) e.port = static_cast<int>(v);
    if (reg_get_dword(key, L"Mode", v) && v < mode_choices().size()) e.mode = static_cast<int>(v);
    if (reg_get_dword(key, L"Codec", v) && v < codec_choices().size()) e.codec = static_cast<int>(v);
    if (reg_get_dword(key, L"ResolutionMode", v) && v < resolution_choices().size()) e.resolution = static_cast<int>(v);
    if (reg_get_dword(key, L"Curtain", v)) e.curtain = v != 0;
    if (reg_get_dword(key, L"TwoDisplays", v)) e.two_displays = v != 0;
    RegCloseKey(key);
    if (!e.host.empty() && !e.user.empty()) out.push_back(std::move(e));
  }
  return out;
}

// 保存するのは接続したことのあるMacだけ。保存済みのパスワードから分かるMacは、
// ここに保存しなくても一覧に戻ってくる。
void save_history(const std::vector<HostEntry>& list) {
  RegDeleteTreeW(HKEY_CURRENT_USER, kHostsKey);
  size_t n = 0;
  for (const HostEntry& e : list) {
    if (!e.has_options) continue;
    HKEY key;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, std::format(L"{}\\{}", kHostsKey, n++).c_str(), 0, nullptr, 0, KEY_WRITE,
                        nullptr, &key, nullptr) != ERROR_SUCCESS) {
      return;
    }
    auto put_str = [&](const wchar_t* name, const std::wstring& v) {
      RegSetValueExW(key, name, 0, REG_SZ, reinterpret_cast<const BYTE*>(v.c_str()),
                     static_cast<DWORD>((v.size() + 1) * sizeof(wchar_t)));
    };
    auto put_dword = [&](const wchar_t* name, DWORD v) {
      RegSetValueExW(key, name, 0, REG_DWORD, reinterpret_cast<const BYTE*>(&v), sizeof(v));
    };
    put_str(L"Host", e.host);
    put_str(L"User", e.user);
    put_dword(L"Port", static_cast<DWORD>(e.port));
    put_dword(L"Mode", static_cast<DWORD>(e.mode));
    put_dword(L"Codec", static_cast<DWORD>(e.codec));
    put_dword(L"ResolutionMode", static_cast<DWORD>(e.resolution));
    put_dword(L"Curtain", e.curtain ? 1 : 0);
    put_dword(L"TwoDisplays", e.two_displays ? 1 : 0);
    RegCloseKey(key);
  }
}

HostEntry entry_from(const ConnectSettings& s) {
  HostEntry e;
  e.host = s.host;
  e.port = s.port;
  e.user = s.user;
  e.has_options = true;
  e.mode = s.mode;
  e.codec = s.codec;
  e.resolution = s.resolution;
  e.curtain = s.curtain;
  e.two_displays = s.two_displays;
  return e;
}

std::wstring get_text(HWND dlg, int id) {
  HWND h = GetDlgItem(dlg, id);
  int n = GetWindowTextLengthW(h);
  std::wstring s(static_cast<size_t>(n) + 1, L'\0');
  GetWindowTextW(h, s.data(), n + 1);
  s.resize(static_cast<size_t>(n));
  s.erase(0, s.find_first_not_of(L" \t"));
  s.erase(s.find_last_not_of(L" \t") + 1);
  return s;
}

// ここまでに入力されたホスト、ポート、ユーザーを一覧の項目の形で返す（ポートが数でなければ0）。
HostEntry typed_target(HWND dlg) {
  HostEntry e;
  e.host = get_text(dlg, IDC_HOST);
  e.user = get_text(dlg, IDC_USER);
  BOOL ok = FALSE;
  const UINT port = GetDlgItemInt(dlg, IDC_PORT, &ok, FALSE);
  e.port = ok ? static_cast<int>(port) : 0;
  return e;
}

void fill_profiles(HWND dlg, const DialogState& st) {
  HWND combo = GetDlgItem(dlg, IDC_PROFILE);
  ComboBox_ResetContent(combo);
  ComboBox_AddString(combo, L"(新しい接続先)");
  for (const HostEntry& e : st.entries) ComboBox_AddString(combo, entry_label(e).c_str());
}

// ホスト、ポート、ユーザーが変わったあとに呼ぶ。それに合う接続先の項目（なければ
// 新しい接続先）を選び、パスワードが保存されているかを示す（`keep_save_box` で
// なければ「パスワードを保存する」のチェックも合わせる）。
void match_typed_target(HWND dlg, const DialogState& st, bool keep_save_box = false) {
  const HostEntry t = typed_target(dlg);
  int index = 0;
  for (size_t i = 0; i < st.entries.size() && !index; ++i) {
    if (same_target(st.entries[i], t)) index = static_cast<int>(i) + 1;
  }
  ComboBox_SetCurSel(GetDlgItem(dlg, IDC_PROFILE), index);
  EnableWindow(GetDlgItem(dlg, IDC_PROFILE_DELETE), index > 0 && !st.connecting);
  const bool saved = t.port > 0 && load_password(t.host, t.port, t.user).has_value();
  if (!keep_save_box) CheckDlgButton(dlg, IDC_SAVE_PASSWORD, saved ? BST_CHECKED : BST_UNCHECKED);
  SetDlgItemTextW(dlg, IDC_NOTE,
                  saved ? L"このホストとユーザーのパスワードは保存済みです。パスワード欄が空なら、保存済みのものを使います。"
                        : L"接続すると、このウィンドウでのキーボードとマウスの操作が Mac に送られます。");
}

// コーデックが関係するのは高パフォーマンスモードだけ。
void enable_codec(HWND dlg, const DialogState& st) {
  const int mode = ComboBox_GetCurSel(GetDlgItem(dlg, IDC_MODE));
  EnableWindow(GetDlgItem(dlg, IDC_CODEC), !st.connecting && mode >= 0 && mode_choices()[mode].quality.empty());
}

void show_options(HWND dlg, const DialogState& st, int mode, int codec, int resolution, bool curtain,
                  bool two_displays) {
  ComboBox_SetCurSel(GetDlgItem(dlg, IDC_MODE), mode);
  ComboBox_SetCurSel(GetDlgItem(dlg, IDC_CODEC), codec);
  enable_codec(dlg, st);
  ComboBox_SetCurSel(GetDlgItem(dlg, IDC_RESOLUTION), resolution);
  CheckDlgButton(dlg, IDC_CURTAIN, curtain ? BST_CHECKED : BST_UNCHECKED);
  CheckDlgButton(dlg, IDC_TWO_DISPLAYS, two_displays ? BST_CHECKED : BST_UNCHECKED);
}

// 接続先を選んだとき。そのホスト、ポート、ユーザーと、（分かっていれば）
// 前回使ったオプションを入力欄に入れる。
void pick_profile(HWND dlg, DialogState& st, int index) {
  st.filling = true;
  SetDlgItemTextW(dlg, IDC_PASSWORD, L"");
  if (index <= 0 || index > static_cast<int>(st.entries.size())) {
    SetDlgItemTextW(dlg, IDC_HOST, L"");
    SetDlgItemInt(dlg, IDC_PORT, 5900, FALSE);
    SetDlgItemTextW(dlg, IDC_USER, L"");
  } else {
    const HostEntry& e = st.entries[index - 1];
    SetDlgItemTextW(dlg, IDC_HOST, e.host.c_str());
    SetDlgItemInt(dlg, IDC_PORT, static_cast<UINT>(e.port), FALSE);
    SetDlgItemTextW(dlg, IDC_USER, e.user.c_str());
    if (e.has_options) show_options(dlg, st, e.mode, e.codec, e.resolution, e.curtain, e.two_displays);
  }
  st.filling = false;
  match_typed_target(dlg, st);
  const bool saved = IsDlgButtonChecked(dlg, IDC_SAVE_PASSWORD) == BST_CHECKED;
  SetFocus(GetDlgItem(dlg, index <= 0 ? IDC_HOST : saved ? IDOK : IDC_PASSWORD));
}

void delete_profile(HWND dlg, DialogState& st) {
  const int index = ComboBox_GetCurSel(GetDlgItem(dlg, IDC_PROFILE)) - 1;
  if (index < 0 || index >= static_cast<int>(st.entries.size())) return;
  const HostEntry e = st.entries[index];
  const std::wstring ask = std::format(L"接続先「{}」を一覧から削除しますか？\n保存したパスワードがあれば、それも削除します。",
                                       entry_label(e));
  if (MessageBoxW(dlg, ask.c_str(), L"iShareScreen", MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2) != IDYES) return;
  st.entries.erase(st.entries.begin() + index);
  forget_password(e.host, e.port, e.user);
  save_history(st.entries);
  fill_profiles(dlg, st);
  match_typed_target(dlg, st);
}

void init_dialog(HWND dlg, DialogState& st) {
  const ConnectSettings& s = *st.settings;
  // 接続したことのあるMac、前回の接続の設定（一覧ができる前に保存したもの）、
  // パスワードが保存されているMacの順に並べる。
  st.entries = load_history();
  if (!s.host.empty() && !s.user.empty()) merge_entries(st.entries, {entry_from(s)}, kMaxHosts);
  std::vector<HostEntry> saved;
  for (const std::wstring& t : saved_password_targets()) {
    if (auto e = parse_credential_target(t)) saved.push_back(std::move(*e));
  }
  merge_entries(st.entries, saved, kMaxHosts);
  fill_profiles(dlg, st);

  HWND mode = GetDlgItem(dlg, IDC_MODE);
  for (const auto& m : mode_choices()) ComboBox_AddString(mode, m.label.c_str());
  HWND codec = GetDlgItem(dlg, IDC_CODEC);
  for (const auto& c : codec_choices()) ComboBox_AddString(codec, c.label.c_str());
  HWND res = GetDlgItem(dlg, IDC_RESOLUTION);
  for (const auto& r : resolution_choices()) ComboBox_AddString(res, r.label.c_str());
  HWND gpu = GetDlgItem(dlg, IDC_GPU);
  ComboBox_AddString(gpu, L"自動 (高性能 GPU を優先)");
  for (const auto& g : *st.gpus) {
    ComboBox_AddString(gpu, std::format(L"[{}] {}{}", g.index, g.name, g.software ? L" (software)" : L"").c_str());
  }
  ComboBox_SetCurSel(gpu, s.gpu + 1);
  show_options(dlg, st, s.mode, s.codec, s.resolution, s.curtain, s.two_displays);

  st.filling = true;
  SetDlgItemTextW(dlg, IDC_HOST, s.host.c_str());
  SetDlgItemInt(dlg, IDC_PORT, static_cast<UINT>(s.port), FALSE);
  SetDlgItemTextW(dlg, IDC_USER, s.user.c_str());
  st.filling = false;
  match_typed_target(dlg, st);
  SetFocus(GetDlgItem(dlg, s.host.empty() ? IDC_HOST : IDC_PASSWORD));
}

// 入力されたままのパスワード。ほかの欄と違い、前後の空白を削らない。
std::wstring get_password(HWND dlg) {
  HWND h = GetDlgItem(dlg, IDC_PASSWORD);
  int n = GetWindowTextLengthW(h);
  std::wstring s(static_cast<size_t>(n) + 1, L'\0');
  GetWindowTextW(h, s.data(), n + 1);
  s.resize(static_cast<size_t>(n));
  return s;
}

// 接続中はキャンセルボタンだけ使えるようにする。
void set_connecting(HWND dlg, DialogState& st, bool on) {
  st.connecting = on;
  for (int id : {IDC_PROFILE, IDC_HOST, IDC_PORT, IDC_USER, IDC_PASSWORD, IDC_SAVE_PASSWORD, IDC_MODE, IDC_RESOLUTION,
                 IDC_GPU, IDC_CURTAIN, IDC_TWO_DISPLAYS, IDOK}) {
    EnableWindow(GetDlgItem(dlg, id), !on);
  }
  enable_codec(dlg, st);
  if (on) {
    EnableWindow(GetDlgItem(dlg, IDC_PROFILE_DELETE), FALSE);
    SetDlgItemTextW(dlg, IDC_NOTE, std::format(L"{}:{} に接続しています… (Mac 側で許可が必要なことがあります)",
                                               st.pending.host, st.pending.port).c_str());
    SetFocus(GetDlgItem(dlg, IDCANCEL));
  } else {
    match_typed_target(dlg, st, true);
  }
}

// 接続ボタン。入力欄を確かめ、その値で接続を始める。
bool accept(HWND dlg, DialogState& st) {
  ConnectSettings& s = st.pending;
  s = *st.settings;
  std::wstring host = get_text(dlg, IDC_HOST);
  if (host.empty()) {
    MessageBoxW(dlg, L"ホストを入力してください。", L"iShareScreen", MB_ICONWARNING);
    SetFocus(GetDlgItem(dlg, IDC_HOST));
    return false;
  }
  BOOL ok = FALSE;
  UINT port = GetDlgItemInt(dlg, IDC_PORT, &ok, FALSE);
  if (!ok || port == 0 || port > 65535) {
    MessageBoxW(dlg, L"ポートは 1〜65535 で指定してください。", L"iShareScreen", MB_ICONWARNING);
    SetFocus(GetDlgItem(dlg, IDC_PORT));
    return false;
  }
  std::wstring user = get_text(dlg, IDC_USER);
  if (user.empty()) {
    MessageBoxW(dlg, L"ユーザー名を入力してください。", L"iShareScreen", MB_ICONWARNING);
    SetFocus(GetDlgItem(dlg, IDC_USER));
    return false;
  }
  std::wstring password = get_password(dlg);
  const bool remember = IsDlgButtonChecked(dlg, IDC_SAVE_PASSWORD) == BST_CHECKED;
  if (password.empty()) {
    if (auto saved = load_password(host, static_cast<int>(port), user)) password = std::move(*saved);
  }
  if (password.empty()) {
    MessageBoxW(dlg, L"パスワードを入力してください。", L"iShareScreen", MB_ICONWARNING);
    SetFocus(GetDlgItem(dlg, IDC_PASSWORD));
    return false;
  }
  s.host = host;
  s.port = static_cast<int>(port);
  s.user = user;
  s.password = std::move(password);
  s.resolution = std::max(0, ComboBox_GetCurSel(GetDlgItem(dlg, IDC_RESOLUTION)));
  s.mode = std::max(0, ComboBox_GetCurSel(GetDlgItem(dlg, IDC_MODE)));
  s.codec = std::max(0, ComboBox_GetCurSel(GetDlgItem(dlg, IDC_CODEC)));
  s.gpu = ComboBox_GetCurSel(GetDlgItem(dlg, IDC_GPU)) - 1;
  s.curtain = IsDlgButtonChecked(dlg, IDC_CURTAIN) == BST_CHECKED;
  s.two_displays = IsDlgButtonChecked(dlg, IDC_TWO_DISPLAYS) == BST_CHECKED;
  st.remember = remember;
  set_connecting(dlg, st, true);
  (*st.connect)(s, dlg);
  return true;
}

// 接続の結果を受け取る。パスワード、設定、接続先の一覧は接続できた今になって
// 初めて保存する。こうすれば打ち間違いや誤ったパスワードは保存されない。
void finish(HWND dlg, DialogState& st, bool connected, const std::wstring& why) {
  ConnectSettings& s = st.pending;
  set_connecting(dlg, st, false);
  if (connected) {
    if (st.remember) {
      save_password(s.host, s.port, s.user, s.password);
    } else {
      forget_password(s.host, s.port, s.user);
    }
    secure_wipe(s.password.data(), s.password.size() * sizeof(wchar_t));
    s.password.clear();
    save(s, *st.gpus);
    remember_entry(st.entries, entry_from(s), kMaxHosts);
    save_history(st.entries);
    *st.settings = s;
    // パスワードを必要以上に長くコントロールに残さない。
    SetDlgItemTextW(dlg, IDC_PASSWORD, L"");
    EndDialog(dlg, IDOK);
    return;
  }
  secure_wipe(s.password.data(), s.password.size() * sizeof(wchar_t));
  s.password.clear();
  MessageBoxW(dlg, (L"接続できませんでした。\n\n" + why).c_str(), L"iShareScreen", MB_ICONERROR);
  SetFocus(GetDlgItem(dlg, IDC_HOST));
}

INT_PTR CALLBACK dialog_proc(HWND dlg, UINT msg, WPARAM wp, LPARAM lp) {
  auto* st = reinterpret_cast<DialogState*>(GetWindowLongPtrW(dlg, DWLP_USER));
  switch (msg) {
    case WM_INITDIALOG:
      SetWindowLongPtrW(dlg, DWLP_USER, lp);
      init_dialog(dlg, *reinterpret_cast<DialogState*>(lp));
      return FALSE;  // フォーカスは設定済み
    case WM_APP_CONNECT_RESULT: {
      std::unique_ptr<std::wstring> why(reinterpret_cast<std::wstring*>(lp));
      if (st && st->connecting) finish(dlg, *st, wp != 0, why ? *why : std::wstring());
      return TRUE;
    }
    case WM_COMMAND:
      switch (LOWORD(wp)) {
        case IDOK:
          if (!st->connecting) accept(dlg, *st);
          return TRUE;
        case IDCANCEL:
          SetDlgItemTextW(dlg, IDC_PASSWORD, L"");
          secure_wipe(st->pending.password.data(), st->pending.password.size() * sizeof(wchar_t));
          EndDialog(dlg, IDCANCEL);
          return TRUE;
        case IDC_PROFILE:
          if (HIWORD(wp) == CBN_SELCHANGE) pick_profile(dlg, *st, ComboBox_GetCurSel(GetDlgItem(dlg, IDC_PROFILE)));
          return TRUE;
        case IDC_PROFILE_DELETE:
          if (HIWORD(wp) == BN_CLICKED) delete_profile(dlg, *st);
          return TRUE;
        case IDC_MODE:
          if (HIWORD(wp) == CBN_SELCHANGE) enable_codec(dlg, *st);
          return TRUE;
        case IDC_HOST:
        case IDC_PORT:
        case IDC_USER:
          if (HIWORD(wp) == EN_CHANGE && st && !st->filling) match_typed_target(dlg, *st);
          return TRUE;
      }
      break;
  }
  return FALSE;
}

}  // namespace

// H.264ではホストがバッキングストアを3840x2160までに抑え、それを超えると小さな
// 既定値（960x540ポイント）にする。そのため2xの選択肢は最大1920x1080
// ポイントで、それより大きいものはHEVCが要る（H.264では収まるよう縮める）。
// レジストリはインデックスで保存するので、新しい選択肢は末尾に足す。
const std::vector<ResolutionChoice>& resolution_choices() {
  static const std::vector<ResolutionChoice> kChoices = {
      {L"自動 (ウィンドウに合わせ、サイズ変更に追従)", 0, 0, 0},
      {L"1920×1080 (Retina 2x)", 1920, 1080, 2.0},
      {L"1440×900 (Retina 2x)", 1440, 900, 2.0},
      {L"1920×1080 (等倍 1x)", 1920, 1080, 1.0},
      {L"2560×1440 (等倍 1x)", 2560, 1440, 1.0},
      {L"3840×2160 (等倍 1x)", 3840, 2160, 1.0},
      {L"2560×1440 (Retina 2x、5K、HEVC のみ)", 2560, 1440, 2.0},
  };
  return kChoices;
}

const std::vector<CodecChoice>& codec_choices() {
  static const std::vector<CodecChoice> kChoices = {
      {L"H.264 (3840×2160 まで)", false, false},
      {L"HEVC 4:2:0 (5K 以上、試験中)", true, true},
      {L"HEVC 4:4:4 (5K 以上、Intel GPU のみ、試験中)", true, false},
  };
  return kChoices;
}

const std::vector<ModeChoice>& mode_choices() {
  // 画面共有アプリの2つの画質は"full"（ロスレス32ビット）と
  // "adaptive"（AppleのDCTコーデック）。
  static const std::vector<ModeChoice> kChoices = {
      {L"高パフォーマンス (Apple シリコンの Mac)", L"高パフォーマンス", L""},
      {L"標準: 約 3 万色 (どの Mac でも)", L"約 3 万色", L"thousands"},
      {L"標準: 高画質 (約 1670 万色、帯域を多く使う)", L"高画質", L"millions"},
      {L"標準: 適応 (帯域が少なく、画質は粗め)", L"適応", L"adaptive"},
      {L"標準: 16 階調グレー", L"16 階調グレー", L"gray"},
      {L"標準: 白黒", L"白黒", L"bw"},
  };
  return kChoices;
}

void load_saved_settings(ConnectSettings& s, const std::vector<GpuInfo>& gpus) { load_saved_impl(s, gpus); }

void save_mode(int mode) {
  HKEY key;
  if (RegCreateKeyExW(HKEY_CURRENT_USER, kRegKey, 0, nullptr, 0, KEY_WRITE, nullptr, &key, nullptr) != ERROR_SUCCESS) {
    return;
  }
  const DWORD v = static_cast<DWORD>(mode);
  RegSetValueExW(key, L"Mode", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&v), sizeof(v));
  RegCloseKey(key);
}

bool show_connect_dialog(HINSTANCE inst, HWND parent, const std::vector<GpuInfo>& gpus, ConnectSettings& io,
                         const ConnectFn& connect) {
  load_saved_impl(io, gpus);
  DialogState st{&gpus, &io, &connect};
  return DialogBoxParamW(inst, MAKEINTRESOURCEW(IDD_CONNECT), parent, dialog_proc,
                         reinterpret_cast<LPARAM>(&st)) == IDOK;
}

}  // namespace iss::app
